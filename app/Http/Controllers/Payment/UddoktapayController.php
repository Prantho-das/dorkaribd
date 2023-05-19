<?php

namespace App\Http\Controllers\Payment;

use App\Library\UddoktaPay;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\CustomerPackage;
use App\Models\SellerPackage;
use App\Models\CombinedOrder;
use App\Models\Wallet;
use App\Models\User;
use App\Models\Order;
use App\Http\Controllers\CustomerPackageController;
use App\Http\Controllers\SellerPackageController;
use App\Http\Controllers\WalletController;
use App\Http\Controllers\CheckoutController;
use Session;
use Auth;

class UddoktapayController extends Controller
{
    public function pay(){
        $amount = 0;
        if(Session::has('payment_type')){
            if(Session::get('payment_type') == 'cart_payment'){
                $combined_order = CombinedOrder::findOrFail(Session::get('combined_order_id'));
                $amount = round($combined_order->grand_total);
            }
            elseif (Session::get('payment_type') == 'wallet_payment') {
                $amount = round(Session::get('payment_data')['amount']);
            }
            elseif (Session::get('payment_type') == 'customer_package_payment') {
                $customer_package = CustomerPackage::findOrFail(Session::get('payment_data')['customer_package_id']);
                $amount = round($customer_package->amount);
            }
            elseif (Session::get('payment_type') == 'seller_package_payment') {
                $seller_package = SellerPackage::findOrFail(Session::get('payment_data')['seller_package_id']);
                $amount = round($seller_package->amount);
            }
        }
        

        $fields = [
            'full_name'     => isset(Auth::user()->name) ? Auth::user()->name : "John Doe",
            'email'         => isset(Auth::user()->email) ? Auth::user()->email : "John Doe",
            'amount'        => $amount,
            'metadata'      => [
                'user_id'               => Auth::user()->id,
                'payment_type'          => Session::get('payment_type'),
                'combined_order_id'     => Session::get('combined_order_id'),
                'payment_data'          => Session::get('payment_data')
            ],
            'redirect_url'  =>  route('uddoktapay.success'),
            'return_type'   => 'GET',
            'cancel_url'    => route('uddoktapay.cancel'),
            'webhook_url'   => route('uddoktapay.webhook')
        ];
        
        $paymentUrl = UddoktaPay::init_payment($fields);
        return redirect($paymentUrl);
    }

    public function success(Request $request){
        if(empty($request->invoice_id))
        {
            die('Invalid Request');
        }
        $data = UddoktaPay::verify_payment($request->invoice_id);
        if (isset($data['status']) && $data['status'] == 'COMPLETED') {
            $payment_type = Session::get('payment_type');
            if ($payment_type == 'cart_payment') {
                return (new CheckoutController)->checkout_done(Session::get('combined_order_id'), json_encode($data));
            }
            if ($payment_type == 'wallet_payment') {
                return (new WalletController)->wallet_payment_done(Session::get('payment_data'), json_encode($data));
            }
            if ($payment_type == 'customer_package_payment') {
                return (new CustomerPackageController)->purchase_payment_done(Session::get('payment_data'), json_encode($data));
            }
            if($payment_type == 'seller_package_payment') {
                return (new SellerPackageController)->purchase_payment_done(Session::get('payment_data'), json_encode($data));
            }
        }
        else
        {
            flash(translate('Payment pending. Please wait a few moments.'))->error();
            return redirect()->route('dashboard');
        }
    }
    
    public function cancel(Request $request)
    {
        flash(translate('Payment cancelled'))->error();
        return redirect()->route('cart');
    }
    
    
    public function webhook(Request $request)
    {
        $headerAPI = isset( $_SERVER['HTTP_RT_UDDOKTAPAY_API_KEY'] ) ? $_SERVER['HTTP_RT_UDDOKTAPAY_API_KEY'] : NULL;

        if (empty($headerAPI)) {
            return response( "Api key not found", 403 );
        }

        if ( $headerAPI != env( "UDDOKTAPAY_API_KEY" ) ) {
            return response( "Unauthorized Action", 403 );
        }
        
        $bodyContent = trim($request->getContent());
        $bodyData = json_decode($bodyContent);
        $data = UddoktaPay::verify_payment($bodyData->invoice_id);
        $payment_details = json_encode($data);
        if (isset($data['status']) && $data['status'] == 'COMPLETED') {
            $metadata = $data['metadata'];
            if ($metadata['payment_type'] == 'cart_payment') {
                $combined_order = CombinedOrder::findOrFail($metadata['combined_order_id']);
                foreach ($combined_order->orders as $key => $order) {
                    $order = Order::findOrFail($order->id);
                    $order->payment_status = 'paid';
                    $order->payment_details = $payment_details;
                    $order->save();
        
                    calculateCommissionAffilationClubPoint($order);
                }
            } elseif ($metadata['payment_type'] == 'wallet_payment') {
                $user = User::findOrFail($metadata['user_id']);
                $user->balance = $user->balance + $metadata['payment_data']['amount'];
                $user->save();
        
                $wallet = new Wallet;
                $wallet->user_id = $user->id;
                $wallet->amount = $metadata['payment_data']['amount'];
                $wallet->payment_method = $data['payment_method'];
                $wallet->payment_details = $payment_details;
                $wallet->save();
            } elseif ($metadata['payment_type'] == 'customer_package_payment') {
                $user = User::findOrFail($metadata['user_id']);
                $user->customer_package_id = $metadata['payment_data']['customer_package_id'];
                $customer_package = CustomerPackage::findOrFail($metadata['payment_data']['customer_package_id']);
                $user->remaining_uploads += $customer_package->product_upload;
                $user->save();
            } elseif ($metadata['payment_type'] == 'seller_package_payment') {
            }
        }
    }
}