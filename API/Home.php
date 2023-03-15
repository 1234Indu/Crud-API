<?php

namespace App\Controllers\API;
use App\Controllers\BaseController;
use Stripe;
use CodeIgniter\API\ResponseTrait;
use App\Models\UserModel;
use App\Models\RegisterRequestModel;
use App\Models\PageModel;
use App\Models\SupportModel;
use App\Models\CardModel;
use App\Models\BusinessCategoryModel;
use App\Models\BusinessDetailModel;
use App\Models\ProvinceModel;
use App\Models\PlanModel;
use App\Models\BusinessWorkingHourModel;
use App\Models\AssignedBusinessCategoryModel;
use App\Models\ServiceCategoryModel;
use App\Models\AssignedBusinessServiceModel;
use App\Models\SubServiceModel;
use App\Models\EmployeeModel;
use App\Models\FavouriteModel;
use App\Models\AddBookingModel;
use App\Models\BookingsServicesModel;
use App\Models\EmployeeServiceModel;
use App\Models\EmployeeSubServiceModel;
use App\Models\EmployeePortfolioModel;
use App\Models\EmployeeWorkingHourModel;
use App\Models\EmployeeBreakModel;
use App\Models\BusinessDetailAdditionalInformationModel;
use App\Models\BusinessDetailsWebsiteInfModel;
use App\Models\BusinessPortfolioModel;
use App\Models\AddCouponModel;
use App\Models\AssignedCouponServicesModel;
use App\Models\BusinessBreakModel;
use App\Models\AddBusinessWorkingHoursModel;
use App\Models\AddEmpWorkingHoursModel;
use App\Models\SetRecurringBookingModel;
use App\Models\BusinessHoursModel;
use App\Models\EmployeeHoursModel;
use App\Models\AdvertisedBusinessModel;
use App\Models\RateReviewBusinessEmployeeModel;
use App\Models\CancelBookingsModel;
use App\Models\RatedBookingsServicesModel;
use App\Models\PaymentInfoModel;
use App\Models\AdvertisedBusinessPaymentModel;
use App\Models\BusinessPaymentTypeModel;
use App\Models\NotificationSettingsModel;
use App\Models\PlanPaymentModel;

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;
use CodeIgniter\I18n\Time;
use Twilio\Rest\Client;
use CodeIgniter\Files\File;

class Home extends BaseController
{
    use ResponseTrait;
    private $db;

    public function __construct(){
        $this->db = db_connect();
        $this->UserModel = new UserModel();
        $this->RegisterRequestModel = new RegisterRequestModel();
        $this->PageModel = new PageModel();
        $this->SupportModel = new SupportModel();
        $this->CardModel = new CardModel();
        $this->BusinessCategoryModel = new BusinessCategoryModel();
        $this->BusinessDetailModel = new BusinessDetailModel();
        $this->ProvinceModel = new ProvinceModel();
        $this->PlanModel = new PlanModel();
        $this->BusinessWorkingHourModel = new BusinessWorkingHourModel();
        $this->AssignedBusinessCategoryModel = new AssignedBusinessCategoryModel();
        $this->ServiceCategoryModel = new ServiceCategoryModel();
        $this->AssignedBusinessServiceModel = new AssignedBusinessServiceModel();
        $this->SubServiceModel = new SubServiceModel();
        $this->EmployeeModel = new EmployeeModel();
        $this->FavouriteModel = new FavouriteModel();
        $this->AddBookingModel = new AddBookingModel();
        $this->BookingsServicesModel = new BookingsServicesModel();
        $this->EmployeeServiceModel = new EmployeeServiceModel();
        $this->EmployeeSubServiceModel = new EmployeeSubServiceModel();
        $this->EmployeePortfolioModel = new EmployeePortfolioModel();
        $this->EmployeeWorkingHourModel = new EmployeeWorkingHourModel();
        $this->EmployeeBreakModel = new EmployeeBreakModel();
        $this->BusinessDetailAdditionalInformationModel = new BusinessDetailAdditionalInformationModel();
        $this->BusinessDetailsWebsiteInfModel = new BusinessDetailsWebsiteInfModel();
        $this->BusinessPortfolioModel = new BusinessPortfolioModel();
        $this->AddCouponModel = new AddCouponModel();
        $this->AssignedCouponServicesModel = new AssignedCouponServicesModel();
        $this->BusinessBreakModel = new BusinessBreakModel();
        $this->AddBusinessWorkingHoursModel = new AddBusinessWorkingHoursModel();
        $this->AddEmpWorkingHoursModel = new AddEmpWorkingHoursModel();
        $this->SetRecurringBookingModel = new SetRecurringBookingModel();
        $this->BusinessHoursModel = new BusinessHoursModel();
        $this->EmployeeHoursModel = new EmployeeHoursModel();
        $this->AdvertisedBusinessModel = new AdvertisedBusinessModel();
        $this->RateReviewBusinessEmployeeModel = new RateReviewBusinessEmployeeModel();
        $this->CancelBookingsModel = new CancelBookingsModel();
        $this->RatedBookingsServicesModel = new RatedBookingsServicesModel();
        $this->PaymentInfoModel = new PaymentInfoModel();
        $this->AdvertisedBusinessPaymentModel = new AdvertisedBusinessPaymentModel();
        $this->BusinessPaymentTypeModel = new BusinessPaymentTypeModel();
        $this->NotificationSettingsModel = new NotificationSettingsModel();
        $this->PlanPaymentModel = new PlanPaymentModel();
    }

    private function getjwtKey(){
        return getenv('JWT_SECRET');
    }
   
    public function encodeToken($token) {
        $key = $this->getjwtKey();
        $iat = time(); // current timestamp value
        $nbf = $iat + 10;
        //$exp = $iat + 3600; //1 hour
        $exp = $iat + 15780000; //6 months
      
        $payload = array(
            "iss" => "The_claim",
            "aud" => "The_Aud",
            "sub" => "Subject of the JWT",
            "iat" => $iat, //Time the JWT issued at
            "exp" => $exp, // Expiration time of token
            "id" => $token['id'],
            "devId" => $token['device_id']
        );
       
        $token = JWT::encode($payload, $key, 'HS256');

        return $token;
    }

    public function empencodeToken($token) {
        $key = $this->getjwtKey();
        $iat = time(); // current timestamp value
        $nbf = $iat + 10;
        //$exp = $iat + 3600; //1 hour
        $exp = $iat + 15780000; //6 months
      
        $payload = array(
            "iss" => "The_claim",
            "aud" => "The_Aud",
            "sub" => "Subject of the JWT",
            "iat" => $iat, //Time the JWT issued at
            "exp" => $exp, // Expiration time of token
            "id" => $token['emp_id'],
            "devId" => $token['emp_device_id']
        );
       
        $token = JWT::encode($payload, $key, 'HS256');

        return $token;
    }

    public function commonDecodeToken(){
        $key = $this->getjwtKey();
        $authHeader = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];

        if(!empty($authHeader)) {
            $arr = explode(" ", $authHeader);

            $token=$arr[1];

            try {
                $decodedToken = JWT::decode($token, new Key($key, 'HS256'));
                $userID = $decodedToken->id;
                $deviceID = $decodedToken->devId;
                return ["userID" => $userID, "deviceID" => $deviceID];
            //} catch ( \Firebase\JWT\ExpiredException $exception ) {
            } catch ( \Exception $exception ) {        
                $response = [
                    'tokenIssue' => 201,
                    'status' => 201,
                    'message' => "Wrong Token",
                ];
                http_response_code(201);
                print_r(json_encode($response, JSON_PRETTY_PRINT));
                exit();
            }     
        }  else {
            return [];
        }     
    }

    public function empcommonDecodeToken(){
        $key = $this->getjwtKey();
        $authHeader = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];

        if(!empty($authHeader)) {
            $arr = explode(" ", $authHeader);

            $token=$arr[1];

            try {
                $decodedToken = JWT::decode($token, new Key($key, 'HS256'));
                $userID = $decodedToken->id;
                $deviceID = $decodedToken->devId;
                return ["userID" => $userID, "deviceID" => $deviceID];
            //} catch ( \Firebase\JWT\ExpiredException $exception ) {
            } catch ( \Exception $exception ) {        
                $response = [
                    'tokenIssue' => 201,
                    'status' => 201,
                    'message' => "Wrong Token",
                ];
                http_response_code(201);
                print_r(json_encode($response, JSON_PRETTY_PRINT));
                exit();
            }     
        }  else {
            return [];
        }     
    }

    public function decodeToken(){
        $decode = $this->commonDecodeToken();
        $userData = $this->UserModel->getWhere(["id" => $decode['userID'], "device_id" => $decode['deviceID']])->getRowArray();
  
        if(!empty($userData)) {
            return $decode['userID'];
        } else{
            $response = [
                'isAuthorized' => 401,
                'status' => 401,
                'message' => "User Unauthorized",
            ];
            //print_r($response, 401);
            http_response_code(401);
            print_r(json_encode($response, JSON_PRETTY_PRINT));
            exit();
        }    
    }
    
    public function empdecodeToken(){
        $decode = $this->empcommonDecodeToken();
        $userData = $this->EmployeeModel->getWhere(["emp_id" => $decode['userID'], "emp_device_id" => $decode['deviceID']])->getRowArray();
  
        if(!empty($userData)) {
            return $decode['userID'];
        } else{
            $response = [
                'isAuthorized' => 401,
                'status' => 401,
                'message' => "User Unauthorized",
            ];
            
            http_response_code(401);
            print_r(json_encode($response, JSON_PRETTY_PRINT));
            exit();
        }    
    }

    private function getsendgridKey(){
        return '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';
    }

    public function sendGridEmail($to_email, $type, $emailData) {
        require 'vendor/autoload.php';

        $sendgridKey = $this->getsendgridKey();
        
        $grid = new \SendGrid\Mail\Mail();
        
        $from_email = "yogesh@parastechnologies.com";
        $receiverEmail = "Indu@parastechnologies.com";
      
        if( ($type == 1) || ($type == 4) || ($type == 5) ) {
            if($emailData['usertype'] == 1) {
                if($type == 1) {
                    $grid->setSubject("Moten E-mail Verification");
                } else if($type == 5) {
                    $grid->setSubject("Moten Forgot Password Verification");
                } else {
                    $grid->setSubject("Moten E-mail Verification");
                }    
            } else {
                if($type == 1) {
                    $grid->setSubject("Moten E-mail Verification");
                } else if($type == 5) {
                    $grid->setSubject("Moten Forgot Password Verification");
                } else {
                    $grid->setSubject("Moten E-mail Verification");
                }      
            }    
            $data['options'] = array('email' => $to_email, 'mobileOtp' => $emailData['mobOtp'], 'userType' => $emailData['usertype'], 'emailType' => $type);
            $message = view('emailTemplate/signup-verification.php',$data);
        }  else if($type == 2) {
            $grid->setSubject("Moten Support");
            $data['options'] = array('username' => $emailData['name'], 'useremail' => $emailData['email'], 'sendemail' => $to_email, 'postuser' => $emailData['posted_by'], 'message' => $emailData['context'], 'emailType' => $type);
            $message = view('emailTemplate/support.php',$data);
        }  else if($type == 3) {
            $grid->setSubject("Verification E-mail");
            $data['options'] = array('email' => $to_email, 'url' => $emailData['link'], 'emailType' => $type);
            $message = view('emailTemplate/forgot-verification.php',$data);
        }  else if($type == 7) {
            $grid->setSubject("Verification E-mail");
            $data['options'] = array('email' => $to_email, 'url' => $emailData['link']);
            $message = view('emailTemplate/employee-verification.php',$data);
        }  else if($type == 8) {
            $grid->setSubject("Moten Support");
            $data['options'] = array('username' => $emailData['name'], 'useremail' => $emailData['email'], 'sendemail' => $to_email, 'postuser' => $emailData['posted_by'], 'message' => $emailData['context'], 'emailType' => $type);
            $message = view('emailTemplate/support.php',$data);
        }else if($type == 9) {
            $grid->setSubject("Moten Booking Payment Reminder");
            $data['options'] = array('useremail' => $to_email,'url' => $emailData['link'],'emailType' => $type,'username'=>$emailData['username'],'booking_id'=>$emailData['booking_id'],'booking_date'=>$emailData['booking_date']);
            $message = view('emailTemplate/booking-payment-reminder.php',$data);
        } else {
            $data['options'] = array('other' => 'other', 'emailType' => $type);
            $message = view('emailTemplate/demo.php',$data);
        }   
        
        $grid->setFrom($from_email, "Moten Inc");
        $grid->addTo($to_email, "Moten Inc");
        $grid->addContent("text/html", $message);
        $sendgrid = new \SendGrid($sendgridKey);

        try {
            $myresponse = $sendgrid->send($grid);
            return $myresponse->statusCode();
        } catch (Exception $e) {
            //$response = array("success"=>0,"message"=>$e->getMessage());
            //echo 'Caught exception: '. $e->getMessage() ."\n";
            return $e->getMessage();
        } 
    }

    protected function sendOtp($data) {
        // Your Account SID and Auth Token from twilio.com/console
        $sid = 'ACa7347bd27b653c0e73b13ef624544592';
        $token = '955ab7b6c29b77224e93b30027a995c3';
        $twilio_number = '+18336815134';

        $client = new Client($sid, $token);

        try {
            $msg = $client->messages->create(
                $data['phone'],
                    array(
                        "from" => $twilio_number,
                        'body' => $data['text']." is your moten app One-Time Verification Code"
                    )
            );

            if($msg->sid) {
                return 1;
            } else {
                return 2;
            }
        } catch(\Twilio\Exceptions\RestException $e){
            return $e->getCode();
            //return $e->getCode() . ' : ' . $e->getMessage()."<br>";
        }    
    }

    public function registerVerify(){
        $userEmail = $this->request->getVar('email');
        $userType = $this->request->getVar('type');

        $checkEmail = $this->UserModel->checkemailTypeExist($userEmail, $userType);

        if($checkEmail > 0) {
            $response=array("status"=>0,"message"=>"An account already exists with this email address. Please login using your email or enter a new email address.");
        } else {
            $checkEmail2 = $this->RegisterRequestModel->checkemailTypeExist($userEmail, $userType);

            $otp = substr(str_shuffle("0123456789"), 0, 4);

            if(!empty($checkEmail2)) {
                $userData = $this->RegisterRequestModel->getdataTypeEmail($userEmail, $userType);

                if($userData['is_complete'] == 0) {
                    $data = array('email_otp' => $otp);
                    $this->RegisterRequestModel->update($userData['id'], $data);

                    $data = array('mobOtp' => $otp, 'usertype' => $userType);
                    $type = 4;

                    $sentEmail = $this->sendGridEmail($userEmail, $type, $data);

                    if($sentEmail == 202) {
                        $response=array("status"=>1,"message"=>"A new verification code has been resent to the email address entered.");
                    } else {
                        $response = array("status"=>0, "message"=>"E-mail not sent");
                    } 
                }  else {
                        $response = array("status"=>2, "message"=>"E-mail already verified");
                }    
            }  else {
                $data = array('email' => $userEmail, 'email_otp' => $otp, 'user_type' => $userType);
                $this->RegisterRequestModel->save($data);

                $data = array('mobOtp' => $otp, 'usertype' => $userType);
                $type = 1;

                $sentEmail = $this->sendGridEmail($userEmail, $type, $data);
                if($sentEmail == 202) {
                    $response=array("status"=>1,"message"=>"A new verification code has been resent to the email address entered.");
                } else {
                    $response = array("status"=>0, "message"=>"E-mail not sent");
                }    
            } 
        }
            return $this->respond($response);
    }

    public function mobileVerification() {
        $userCc = $this->request->getVar('code');
        $userPhn = $this->request->getVar('phone');
        $userOtp = $this->request->getVar('otp');
        
        $userData = $this->RegisterRequestModel->getWhere(["country_code" => $userCc, "mobile" => $userPhn, "mobile_otp" => $userOtp])->getRowArray();

        if(!empty($userData)) {
            $data = array('mobile_otp' => '', 'is_complete' => '2');
            $this->RegisterRequestModel->update($userData['id'], $data);
            $updateduserData = $this->RegisterRequestModel->getdataMobile($userPhn);
            $response = array("status"=>1, "message"=>"Mobile no. verified succesfully.", "data" => $updateduserData);
        } else {
            $response = array("status"=>0, "message"=>"Mobile no. not verified");
        } 
            return $this->respond($response);  
    }

    public function emailVerification() {
        $userEmail = $this->request->getVar('email');
        $userOtp = $this->request->getVar('otp');
        $Type = $this->request->getVar('type');
        $userType = $this->request->getVar('usertype');

        if($Type == 1) {
            $userData = $this->RegisterRequestModel->getWhere(["email" => $userEmail, "email_otp" => $userOtp, "user_type" => $userType])->getRowArray();
        } else {
            $userData = $this->UserModel->getWhere(["email" => $userEmail, "email_otp" => $userOtp, "user_type" => $userType])->getRowArray();
        }    

        if(!empty($userData)) {
            if($Type == 1) {
                $data = array('email_otp' => '', 'is_complete' => '1');
                $this->RegisterRequestModel->update($userData['id'], $data);
                $updateduserData = $this->RegisterRequestModel->getdataTypeEmail($userEmail, $userType);
            } else {
                $data = array('email_otp' => '', 'is_email_verified' => '1');
                $this->UserModel->update($userData['id'], $data);
                $updateduserData = $this->UserModel->loggedInByEmail($userEmail, $userType);
            }    
            $response = array("status"=>1, "message"=>"E-mail verified succesfully.", "data" => $updateduserData);
        } else {
            $response = array("status"=>0, "message"=>"Verification code is incorrect. Please try again or click resend for a new code.");
        } 
            return $this->respond($response);  
    }
    
    public function register() {
        $userFirst = $this->request->getVar('firstname');
        $userLast = $this->request->getVar('lastname');
        $userEmail = $this->request->getVar('email');
        $userCc = $this->request->getVar('code');
        $userPhn = $this->request->getVar('phone');
        $userPwd = $this->request->getVar('password');
        $deviceId = $this->request->getVar('devId');
        $deviceType = $this->request->getVar('devType');
        $deviceToken = $this->request->getVar('devToken');
        $userType = $this->request->getVar('type');
        $userPlan = $this->request->getVar('plan');

        $userData = $this->RegisterRequestModel->getWhere(["email" => $userEmail, "user_type" => $userType])->getRowArray();
        
        if(!empty($userData)) {
            if($userData['is_complete'] == 1) {
                $checkMobile = $this->UserModel->checkmobileExist($userPhn);

                if($checkMobile == 0) {
                    //IF MOBILE NO. DOESN'T EXIST
                    $data = array(
                        'first_name' => $userFirst,
                        'last_name' => $userLast,
                        'email' => $userEmail,
                        'password' => $userPwd,
                        'country_code' => $userCc,
                        'mobile' => $userPhn,
                        'device_id' => $deviceId,
                        'device_type' => $deviceType,
                        'device_token' => $deviceToken,
                        'user_type' => $userData['user_type'],
                        'is_plan' => $userPlan
                    );

                    $result = $this->UserModel->save($data);
                    $lastinsertID = $this->UserModel->getInsertID();

                    if($result == 1) {
                        $this->RegisterRequestModel->where(['email' => $userEmail, 'user_type' => $userType])->delete();
                        $updateduserData = $this->UserModel->get_single_userdata($lastinsertID);
                        $userToken = $this->encodeToken($updateduserData);
                        if($userType == 2) {
                            //Business Default Working Hours
                            /*$allweekDays = array('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun');
                            foreach($allweekDays as $key => $weekDay) :

                                if($weekDay == 'Sun') {
                                    $workData = [
                                                'day' => $weekDay,
                                                'opening_time' => '10:00',   //10:00
                                                'closing_time' => '18:00',   //18:00
                                                'from_break_time' => '13:00', //13:00
                                                'to_break_time' => '14:00',  //14:00
                                                'business_id' => $lastinsertID,
                                                'work_status' => '1'
                                            ]; 
                                } else {
                                    $workData = [
                                                'day' => $weekDay,
                                                'opening_time' => '10:00',
                                                'closing_time' => '18:00',
                                                'from_break_time' => '13:00',
                                                'to_break_time' => '14:00',
                                                'business_id' => $lastinsertID,
                                                'work_status' => '0'
                                            ];
                                }            
                                $this->BusinessWorkingHourModel->save($workData);            
                            endforeach;*/
                            
                            $timings = '[{"day":"Mon","opening_time":"10:00","closing_time":"18:00","work_status":"0","break_time":[{"end_break_time":"14:00","start_break_time":"13:00","week_id": "Mon"}]},{"day":"Tue","opening_time":"10:00","closing_time":"18:00","work_status":"0","break_time":[{"end_break_time":"14:00","start_break_time":"13:00","week_id": "Tue"}]},{"day":"Wed","opening_time":"10:00","closing_time":"18:00","work_status":"0","break_time":[{"end_break_time":"14:00","start_break_time":"13:00","week_id": "Wed"}]},{"day":"Thu","opening_time":"10:00","closing_time":"18:00","work_status":"0","break_time":[{"end_break_time":"14:00","start_break_time":"13:00","week_id": "Thu"}]},{"day":"Fri","opening_time":"10:00","closing_time":"18:00","work_status":"0","break_time":[{"end_break_time":"14:00","start_break_time":"13:00","week_id": "Fri"}]},{"day":"Sat","opening_time":"10:00","closing_time":"18:00","work_status":"0","break_time":[{"end_break_time":"14:00","start_break_time":"13:00","week_id": "Sat"}]},{"day":"Sun","opening_time":"10:00","closing_time":"18:00","work_status":"1","break_time":[{"end_break_time":"14:00","start_break_time":"13:00","week_id": "Sun"}]}]';
                            $created_at	= date('Y-m-d H:i:s');
                            
                            $hours_data = [
                                "business_id" => $lastinsertID,
                                "timings"     => $timings,
                                "created_at"  => $created_at,
                            ];
                            $this->BusinessHoursModel->save($hours_data);   
                        }    
                        
                        
                        $response = array("status"=>1, "message"=>"Registration successfully", "data" => $updateduserData, "token" => $userToken);
                    } else {
                        $response = array("status"=>0, "message"=>"Not Registered", "data" => NULL);
                    } 
                } else {
                     //IF MOBILE NO. EXIST
                    $response = array("status"=>0, "message"=>"Mobile no. already exist");
                }       
            }  else {
                $response = array("status"=>0, "message"=>"Please verify your email");
            } 
        } else {
            $response = array("status"=>0, "message"=>"Email address already exists. Please login or enter a new email address.");
        }  
            return $this->respond($response);         
    }

    public function login() {
        $userEmail = $this->request->getVar('email');
        $userPwd = $this->request->getVar('password');
        $deviceId = $this->request->getVar('devId');
        $deviceType = $this->request->getVar('devType');
        $deviceToken = $this->request->getVar('devToken');
        $userType = $this->request->getVar('type');
        
        $userData = $this->UserModel->loggedInByEmail($userEmail, $userType);
        if(!empty($userData)) {
            if($userData['is_active'] == 0){    
                $pwd_verify = password_verify($userPwd, $userData['password']);
    
                if(!$pwd_verify) {
                    $response=array("status"=>0,"message"=>"The password you have entered is incorrect. Please try again.");
                }  else { 
                    $data = array(
                            'device_id' => $deviceId,
                            'device_type' => $deviceType,
                            'device_token' => $deviceToken
                            );
                    $this->UserModel->update($userData['id'], $data);
          
                    $updateduserData = $this->UserModel->get_single_userdata($userData['id']);
                    $userToken = $this->encodeToken($updateduserData);
                    $response = array("status"=>1, "message"=>"Login data here", "data" => $updateduserData, "token" => $userToken);
                }  
            }else{
                $response = array("status"=>0, "message"=>"You have deactivated your account so, to continue you have to contact your Service administrator!");
            }
        } else {
            $response = array("status"=>0, "message"=>"Sorry, we can't find an account with this email address. Please try again or create a new account.");
        }      
            return $this->respond($response); 
    }                    

    public function getProfile() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            $response = array("status"=>1, "message"=>"User data here", "data" => $userData);
        } else {
            $response = array("status"=>0, "message"=>"User not found", "data" => NULL);
        }  
        return $this->respond($response);
    }

    public function editProfile() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            $file = $this->request->getFile('img');
            $userFirst = $this->request->getVar('firstname');
            $userLast = $this->request->getVar('lastname');
            $userCc = $this->request->getVar('code');
            $userPhn = $this->request->getVar('phone');
            $userEmail = $this->request->getVar('email');
            
            if( ($file != '') && (isset($file)) ) {
                $ext = $file->getClientExtension();
                    
                if( ($ext == "png") || ($ext == "jpg") || ($ext == "gif") || ($ext == "jpeg") ) {
                    $name = $file->getRandomName();

                    $filename = $userData['user_img'];

                    if($filename) {
                        unlink(FCPATH . 'public/userImg/'.$filename);
                    }    

                    $file->move('public/userImg', $name);

                    if( (!empty($userCc)) && (!empty($userPhn)) ) {
                        if( ($userCc == $userData['country_code']) && ($userPhn == $userData['mobile'])) {
                            $data = [
                                'first_name' => $userFirst,
                                'last_name' => $userLast,
                                'user_img' => $name,
                                'email'    => $userEmail
                            ]; 
                        } else {
                            $data = [
                                'first_name' => $userFirst,
                                'last_name' => $userLast,
                                'user_img' => $name,
                                'country_code' => $userCc,
                                'mobile' => $userPhn,
                                'email'    => $userEmail
                            ];   
                        }    
                    } else {
                        $data = [
                            'first_name' => $userFirst,
                            'last_name' => $userLast,
                            'user_img' => $name,
                            'email'    => $userEmail
                        ]; 
                    } 
                        $result = $this->UserModel->update($userData['id'], $data);
                        $userUpdatedData = $this->UserModel->get_single_userdata($userId);
                        $response = array("status"=>1, "message"=>"Profile updated successfully", "data" => $userUpdatedData);
                } else {
                    $response=array("status"=>0,"message"=>"Please upload jpg|png|jpeg|gif image format.");
                }    
            } 
            else {

                if( (!empty($userCc)) && (!empty($userPhn)) ) {
                    if( ($userCc == $userData['country_code']) && ($userPhn == $userData['mobile'])) {
                        $data = [
                            'first_name' => $userFirst,
                            'last_name' => $userLast,
                            'email'    => $userEmail
                        ]; 
                    } else {
                        $data = [
                            'first_name' => $userFirst,
                            'last_name' => $userLast,
                            'country_code' => $userCc,
                            'mobile' => $userPhn,
                            'email'    => $userEmail
                        ];   
                    }    
                } else {
                    $data = [
                        'first_name' => $userFirst,
                        'last_name' => $userLast,
                        'email'    => $userEmail
                    ]; 
                } 
                
                $result = $this->UserModel->update($userData['id'], $data);
                $userUpdatedData = $this->UserModel->get_single_userdata($userId);
                $response = array("status"=>1, "message"=>"Profile updated successfully", "data" => $userUpdatedData);
            }    
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response); 
    }

    public function privacyPolicy() { 
        $user_type = $this->request->getVar('user_type'); //1=User,2=Business,3=Employee
        $pageData = $this->PageModel->getWhere(["slug" => "privacy-policy","user_type" => $user_type])->getRowArray();
        if(!empty($pageData)) {
            $response = array("status"=>1, "message"=>"Privacy Policy found.", "data" => $pageData['page_content']);
        } else {
            $response = array("status"=>0, "message"=>"No Privacy Policy found!", "data" => NULL);
        } 
        return $this->respond($response);    
    }

    public function termCondition() { 
        $user_type = $this->request->getVar('user_type'); //1=User,2=Business,3=Employee
        $pageData = $this->PageModel->getWhere(["slug" => "term-condition","user_type" => $user_type])->getRowArray();
        if(!empty($pageData)) {
            $response = array("status"=>1, "message"=>"Terms & Conditions found.", "data" => $pageData['page_content']);
        } else {
            $response = array("status"=>0, "message"=>"No Terms & Conditions found!", "data" => NULL);
        } 
        return $this->respond($response);    
    }

    public function postSupport() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) { 
            $userName = $this->request->getVar('name');
            $userEmail = $this->request->getVar('email');
            $userConcern = $this->request->getVar('concern');
            
            $data = array('name' => $userName, 'email' => $userEmail, 'user_id' => $userId, 'context' => $userConcern);

            $postedUser = $userData['first_name']." ".$userData['last_name'];

            $maildata = array('name' => $userName, 'email' => $userEmail, 'posted_by' => $postedUser, 'context' => $userConcern);

            $userEmail2 = "parasdinesh8610@gmail.com";

            $type = 2;
           
            $sentEmail = $this->sendGridEmail($userEmail2, $type, $maildata);

            if($sentEmail == 202) {
                $insert = $this->SupportModel->save($data);
                $response = array("status"=>1, "message"=>"Your query has sent successfully.");
            } else {
                $response = array("status"=>0, "message"=>"Your query has not been sent!");
            } 
        } else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);    
    }

    public function changePassword() {
        $userId = $this->decodeToken();

        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) { 
            $currentPwd = $this->request->getVar('oldpwd');
            $newpassword = $this->request->getVar('newpwd');
            
            $pwd_verify = password_verify($currentPwd, $userData['password']);

            if(!$pwd_verify) {
                $response=array("status"=>0,"message"=>"Old password is incorrect. Please try again.");
            }  else { 
                $data = array('password' => $newpassword);
                $result = $this->UserModel->update($userData['id'], $data);

                if($result == 1) {
                    $response=array("status"=>1,"message"=>"password changed successfully");
                } else {
                    $response=array("status"=>1,"message"=>"password not updated");
                }
            }    
        } else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);    
    }

    public function logout() {
        $userId = $this->decodeToken();
        
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) { 
            $key = $this->getjwtKey();

            $iat = time();
            $nbf = $iat + 10;
            $exp = $iat + 15780000;
           
            $payload = array(
                "iss" => "The_claim",
                "aud" => "The_Aud",
                "sub" => "Subject of the JWT",
                "iat" => $iat,
                "id" => $userId,
            );

            $token = JWT::encode($payload, $key, 'HS256');

            $data=array(
                'device_id' => '',
                'device_type' => '',
                'device_token' => '',
                'latitude' => '',
                'longitude' => ''
            );

            $result = $this->UserModel->update($userId, $data);
            $updatedUserData = $this->UserModel->get_single_userdata($userId);
           
            $response=array("status"=>1,"message"=>"Logout successful", "data" => $updatedUserData);
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);         
    }

    public function addCard() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            $holderName = $this->request->getVar('holdername');
            $cardNum = $this->request->getVar('cardnumber');
            $expire = $this->request->getVar('expiredate');

            $data = array(
                'card_holder_name' => $holderName,
                'card_number' => $cardNum,
                'card_expire_date' => $expire,
                'user_id' => $userId
            );  

            $this->CardModel->save($data);
            $lastinsertID = $this->CardModel->getInsertID();

            $cardDtl = $this->CardModel->getcardDetail($lastinsertID);
            $response = array("status"=>1, "message"=>"Card added successfully.", "data" => $cardDtl);
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response);     
    } 

    public function allcardDetails() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) { 
            $cardData = $this->CardModel->getWhere(['user_id' => $userId])->getResultArray();

            if(!empty($cardData)) {
                $response = array("status"=>1, "message"=>"Cards found", "data" => $cardData);
            } else {
                $response = array("status"=>0, "message"=>"Cards data not found", "data" => []);
            }  
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);      
    }

    public function getsingleCardDetails() {
        $userId = $this->decodeToken();
        
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) { 
            $cardID = $this->request->getVar('cardId');
            $cardData = $this->CardModel->getWhere(['id' => $cardID, 'user_id' => $userId])->getRowArray();

            if(!empty($cardData)) {
                $response = array("status"=>1, "message"=>"Cards found", "data" => $cardData);
            } else {
                $response = array("status"=>0, "message"=>"Cards data not found", "data" => NULL);
            }  
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);      
    }

    public function updateCoordinates() {
        $userId = $this->decodeToken();
        
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) { 
            $userLat = $this->request->getVar('lat');
            $userLong = $this->request->getVar('long');
            
            $data = array('latitude' => $userLat, 'longitude' => $userLong);

            $this->UserModel->update($userData['id'], $data);
            $updateduserData = $this->UserModel->get_single_userdata($userData['id']);
            $response = array("status"=>1, "message"=>"User data here", "data" => $updateduserData);
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);      
    }

    public function getbusinessCategories() {
        $userId = $this->decodeToken();
        
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) { 
            if($userData['user_type'] == 2) {
                $businessData = $this->BusinessCategoryModel->findAll();
        
                if(!empty($businessData)) { 
                    foreach($businessData as $key => $bus) :
                        $businessCategory = $bus['id'];
                        $catData = $this->AssignedBusinessCategoryModel->getWhere(['business_id' => $userId, 'bussiness_category_id' => $businessCategory])->getRowArray();
                        if(!empty($catData)) {
                            $businessData[$key]['is_assigned'] = '1';
                        } else {
                            $businessData[$key]['is_assigned'] = '0';
                        }
                    endforeach;
                    $columns = array_column($businessData, 'business_category');
                    array_multisort($columns, SORT_ASC, $businessData);
                    $response = array("status"=>1, "message"=>"Business categories found", "data" => $businessData);
                }  else {
                    $response = array("status"=>0, "message"=>"Business categories not found", "data" => []);
                }
            } else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }      
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);     
    }

    public function changenotificationStatus() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            $userStatus = $this->request->getVar('status'); //0=Off, 1=On
            $data = array('is_notification' => $userStatus);
            $this->UserModel->update($userData['id'], $data);
            
            $updateduserData = $this->UserModel->get_single_userdata($userData['id']);
            if($userStatus == 0) {
                $response = array("status"=>1, "message"=>"Notification status Off.", "data" => $updateduserData);
            } else {
                $response = array("status"=>1, "message"=>"Notification status On.", "data" => $updateduserData);
            }    
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);       
    }

    public function changeprimaryCard() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            $userCard = $this->request->getVar('cardId');

            $cardDtl = $this->CardModel->getcardDetail($userCard);
            
            if(!empty($cardDtl)) {

                $cardData = $this->CardModel->getWhere(['user_id' => $userId])->getResultArray();

                foreach($cardData as $card) :
                    $cardID = $card['id'];
                    $udata = array('is_primary' => '0');
                    $this->CardModel->update($cardID, $udata);
                endforeach;
                
                $data = array('is_primary' => '1');

                $this->CardModel->update($userCard, $data);

                $updatedcardDtl = $this->CardModel->getcardDetail($userCard);

                $response = array("status"=>1, "message"=>"Set as primary Card", "data" => $updatedcardDtl);
            } else {
                $response = array("status"=>0, "message"=>"Card not found", "data" => NULL);
            }
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);     
    }
    
    public function favoriteList() {
        $userId = $this->decodeToken();
        
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            $response = array("status"=>1, "message"=>"User Home screen", "data" => $userData);
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);     
    } 

    public function stafffavoriteList() {
        $userId = $this->decodeToken();
        
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            $response = array("status"=>1, "message"=>"User Home screen", "data" => $userData);
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);     
    }
    
    public function businessfavoriteList() {
        $userId = $this->decodeToken();
        
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            $response = array("status"=>1, "message"=>"User Home screen", "data" => $userData);
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);     
    }

    public function deleteCard() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            $cardID = $this->request->getVar('cardId');

            $cardData = $this->CardModel->getWhere(["id" => $cardID, "user_id" => $userId])->getRowArray();

            if(!empty($cardData)) {
                $this->CardModel->where('id', $cardID)->delete();
                $response = array("status"=>1, "message"=>"Card deleted successfully.");
            }  else {
                $response = array("status"=>0, "message"=>"Card not found");
            } 
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);     
    }
    
    public function forgotPassword() {
        $emailID = $this->request->getVar('email');
        $userType = $this->request->getVar('type');

        $userData = $this->UserModel->loggedInByEmail($emailID, $userType);

        if(!empty($userData)) {
            $random = substr(str_shuffle("0123456789"), 0, 4);
            
            $data = array('email_otp' => $random);
            $this->UserModel->update($userData['id'], $data);
            
            $mobData = array('mobOtp' => $random, 'usertype' => $userType);
            $type = 5;

            $sentEmail = $this->sendGridEmail($emailID, $type, $mobData);

            if($sentEmail == 202) {
                $response=array("status"=>1,"message"=>"A new verification code has been resent to the email address entered.");
            } else {
                $response = array("status"=>0, "message"=>"E-mail not sent");
            } 
        }  else {
            $response = array("status"=>0, "message"=>"Sorry, we can't find an account with this email address. Please try again or create a new account.", "data" => NULL);
        } 
            return $this->respond($response);        
    }

    public function resetPassword() {
        $userEmail = $this->request->getVar('email');
        $userType = $this->request->getVar('type');

        $userData = $this->UserModel->loggedInByEmail($userEmail, $userType);

        if(!empty($userData)) { 
            $newpassword = $this->request->getVar('pwd');

            $data = array('password' => $newpassword);
            $result = $this->UserModel->update($userData['id'], $data);

            if($result == 1) {
                $response=array("status"=>1,"message"=>"password changed successfully");
            } else {
                $response=array("status"=>1,"message"=>"password not updated");
            }
        } else {
            $response = array("status"=>0, "message"=>"Sorry, we can't find an account with this email address. Please try again or create a new account.", "data" => NULL);
        } 
            return $this->respond($response);    
    }
    
    public function addbusinessDetail() {
        $userId = $this->decodeToken();
        
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $userBusiness = $this->request->getVar('businessname');
                $userStreet1 = $this->request->getVar('streetadr1');
                $userStreet2 = $this->request->getVar('streetadr2');
                $userCity = $this->request->getVar('city');
                $userProv = $this->request->getVar('province');
                $userPostal = $this->request->getVar('postal');
                $userCcode = $this->request->getVar('code');
                $userphn = $this->request->getVar('phone');
                $userlatitude = $this->request->getVar('latitude');
                $userlongitude = $this->request->getVar('longitude');
                
                $data = array(
                            'business_name' => $userBusiness,
                            'business_address_1' => $userStreet1,
                            'business_address_2' => $userStreet2,
                            'business_city' => $userCity,
                            'business_province' => $userProv,
                            'business_postal_code' => $userPostal,
                            'business_country_code' => $userCcode,
                            'business_phone' => $userphn,
                            'business_id' => $userId,
                            'business_latitude' => $userlatitude,
                            'business_longitude' => $userlongitude,
                        );
                $this->BusinessDetailModel->save($data);
                
                if($userData['is_step'] <= 2){
                    $udata = array('is_complete' => '1', 'is_step' => '2');
                    $this->UserModel->update($userData['id'], $udata);
                }
                $updateduserData = $this->UserModel->get_single_userdata($userId);
                
                $updated_data = $this->BusinessDetailModel->getWhere(["business_id" => $userId])->getRowArray();
                $response = array("status"=>1, "message"=>"Business details added successfully", "data" => $updated_data); 
            } else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);
    } 
    
    public function getProvince() {
        $provinceData = $this->ProvinceModel->findAll();

        if(!empty($provinceData)) { 
            $columns = array_column($provinceData, 'province_name');
            array_multisort($columns, SORT_ASC, $provinceData);
            $response = array("status"=>1, "message"=>"Provinces found", "data" => $provinceData);
        }  else {
            $response = array("status"=>0, "message"=>"Provinces not found", "data" => []);
        } 
            return $this->respond($response); 
    }
    
    public function getPlans() {
        $planData = $this->PlanModel->findAll();

        if(!empty($planData)) { 
            $response = array("status"=>1, "message"=>"plans found", "data" => $planData);
        }else {
            $response = array("status"=>0, "message"=>"plans not found", "data" => []);
        } 
        return $this->respond($response); 
    }
    
    public function getBusinessPlan() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)){
            $all_plans = $this->PlanModel->findAll();
            if(!empty($all_plans)){
                foreach($all_plans as $key => $plans){
                    if(in_array($userData['is_plan'],$plans)){
                        $all_plans[$key]['status'] = "1";
                    }else{
                        $all_plans[$key]['status'] = "0";
                    }
                }
                $response = array("status"=>1, "message"=>"Plans found.", "data" => $all_plans);
            }else{
                $response = array("status"=>0, "message"=>"Plans not found!", "data" => NULL);
            }
        }else{
            $response = array("status"=>0, "message"=>"User not found", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function changePlan(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)){
            $type = $this->request->getVar('type'); //1=Individual,2=SmallTeam,3=Unlimited
            date_default_timezone_set('UTC');
            $utcOnlyDate = date('Y-m-d');
            
            $business_id = $userData['id'];
            $get_plan_amount = $this->PlanModel->get_plan_amount($type);
            $total_amount = implode(",",$get_plan_amount); 
            $card_id = $this->request->getVar('card_id');
            
            $stripesecretKey = $this->get_stripe_secret_key();
            $stripe = new \Stripe\StripeClient($stripesecretKey);
            
            $token  = $stripe->tokens->create([
                    'card' => [
                        'number'    => '4242 4242 4242 4242',
                        'exp_month' => '12',
                        'exp_year'  => '25',
                        'cvc'       => '789',
                    ]
                ]);
                
            $customer = $stripe->customers->create([
                'email' => $userData['email'],
                'name' => $userData['first_name'],
            ]);
            
            $process_payment = $stripe->paymentIntents->create([
                'amount' => 100 * $total_amount,
                'currency' => 'USD',
                'payment_method_types' => ['card'],
                'customer' => $customer->id,
                'confirmation_method' => 'manual',
                'confirm' => true,
                'payment_method_data' => [
                    'type' => 'card',
                    'card' => [
                        'token' => $this->request->getVar('stripeToken'),
                    ]
                ],
                "description" => "Payment for Plan",
            ]);
            
            if(!empty($process_payment->id)){
                $data = ['is_plan'=>$type,'plan_puchase_date'=>$utcOnlyDate];
                $update = $this->UserModel->update($userData['id'],$data);
                
                $get_card_number = $this->CardModel->getWhere(['id'=>$card_id])->getRowArray(); 
                $get_user_plan = $this->UserModel->getWhere(['id'=>$userData['id']])->getRowArray(); 
                 
                $transactions       = array( 
                    'transaction_id' => $process_payment->id,
                    'source'        => 'stripe', 
                    'amount'        => $total_amount,
                    'business_id'       => $userData['id'], 
                    'plan_id'    => $get_user_plan['is_plan'], 
                    'payment_method_type' => $process_payment->payment_method_types,
                    'name'     => $userData['first_name'],
                    'email' => $userData['email'],
                    'card_number' => $get_card_number['card_number'],
                    'payment_status' => 'paid',
                    'payment_date'   => $utcOnlyDate
                );
                $payment = $this->PlanPaymentModel->insert($transactions);
                
                $lastinsertID = $this->PlanPaymentModel->getInsertID();
                $updated_data = $this->PlanPaymentModel->getWhere(["id" => $lastinsertID])->getRowArray();
                if(!empty($payment) && !empty($update)){
                    $response = array("status"=>1, "message"=>"Plan changed successfully.", "data" => $updated_data);
                }else{
                    $response = array("status"=>0, "message"=>"Plan not changed!", "data" => NULL);
                }
            }else{
                $response=array("status"=>0,"message"=>"Payment failed, please try again!", "data" =>NULL);
            }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function planBillings(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            $business_id = $userData['id'];
            $get_current_plan['current_plan'] = $this->UserModel->get_plan_dtl($business_id);
            $get_current_plan['current_plan']['next_billing_date'] = date('Y-m-d', strtotime($get_current_plan['current_plan']['plan_puchase_date']. ' + 1 months'));
            
            $get_current_plan['billings'] = $this->PlanPaymentModel->getWhere(['business_id'=>$userData['id']])->getResultArray();
            if(!empty($get_current_plan)){
                foreach($get_current_plan['billings'] as $key => $plan_billing){
                    $business_id = $plan_billing['business_id'];
                    
                    $get_plan_details = $this->PlanPaymentModel->billed_plan_details($business_id);
                    if(!empty($get_plan_details)){
                        $get_current_plan['billings'][$key]['plan_dtl'] = $get_plan_details;
                    }else{
                        $get_current_plan['billings'][$key]['plan_dtl'] = [];
                    }
                    
                    $get_current_plan['billings'][$key]['gst'] = "0";
                }
                $response=array("status"=>1,"message"=>"Plan billings found.","data" =>$get_current_plan);
            }else{
                $response=array("status"=>0,"message"=>"No billings found!", "data" =>NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function updatebusinessHours() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $userWeekDay = $this->request->getVar('weekdayId');
                $userOpenTime = $this->request->getVar('openingtime');
                $userCloseTime = $this->request->getVar('closingtime');
                $userFromBreak = $this->request->getVar('frombreak');
                $userToBreak = $this->request->getVar('tobreak');
                $userWorkStatus = $this->request->getVar('workstatus');
                
                $weekData = $this->BusinessWorkingHourModel->getWhere(["id" => $userWeekDay, "business_id" => $userId])->getRowArray(); 
                
                if(!empty($weekData)) {
                    $data = array('opening_time' => $userOpenTime, 'closing_time' => $userCloseTime, 'from_break_time' => $userFromBreak, 'to_break_time' => $userToBreak, 'work_status' => $userWorkStatus);
                    $result = $this->BusinessWorkingHourModel->update($userWeekDay, $data);
                    $updatedworkingHours = $this->BusinessWorkingHourModel->getWhere(["id" => $userWeekDay])->getRowArray();
                    
                    $response = array("status"=>1, "message"=>"Changes saved successfully!", "data" => $updatedworkingHours);
                }  else {
                    $response = array("status"=>0, "message"=>"Working Hours not found", "data" => []);
                }
            } else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }     
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response);     
    }
    
    public function editBusinessWorkingHours(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
    
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $timings = $this->request->getVar('timings');
                $business_user_id = $userData['id'];
                $created_at	= date('Y-m-d H:i:s');
                
                $listBreaks = $this->BusinessHoursModel->getWhere(["business_id" =>$business_user_id])->getRowArray();
                $id = $listBreaks['id'];
                if (!empty($listBreaks)) { //edit
                     $data = [
                                "timings"     => $timings,
                             ];
                            
                    if(!empty($data)){
                        $update = $this->BusinessHoursModel->update($id,$data);
                        $response = array("status"=>1, "message"=>"Business hours updated successfully.", "data" => $update); 
                    }else{
                        $response = array("status"=>0, "message"=>"Business hours not updated, please try again!", "data" => NULL); 
                    }
                } 
                else { //add
                    $data = [
                                "business_id" => $userData['id'],
                                "timings"     => $timings,
                                "created_at"  => $created_at,
                            ];
                            
                    if(!empty($data)){
                        $insert = $this->BusinessHoursModel->insert($data);
                        $response = array("status"=>1, "message"=>"Business working hours added successfully.", "data" => $insert); 
                    }else{
                        $response = array("status"=>0, "message"=>"Business working hours not added, please try again!", "data" => NULL); 
                    }
                }
            } 
            else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }     
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response); 
    }
    
    public function editEmployeeWorkingHours(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
    
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $timings = $this->request->getVar('timings');
                $created_at	= date('Y-m-d H:i:s');
                $emp_id = $this->request->getVar('emp_id');
                
                $listBreaks = $this->EmployeeHoursModel->getWhere(["emp_id" =>$emp_id])->getRowArray();
                $id = $listBreaks['id'];
                if (!empty($listBreaks)) { //edit
                     $data = [
                                "timings"     => $timings,
                             ];
                            
                    if(!empty($data)){
                        $update = $this->EmployeeHoursModel->update($id,$data);
                        $response = array("status"=>1, "message"=>"Employee working hours updated successfully.", "data" => $update); 
                    }else{
                        $response = array("status"=>0, "message"=>"Business working hours not updated, please try again!", "data" => NULL); 
                    }
                } 
                else { //add
                    $data = [
                                "emp_id" => $emp_id,
                                "timings"     => $timings,
                                "created_at"  => $created_at,
                            ];
                            
                    if(!empty($data)){
                        $insert = $this->EmployeeHoursModel->insert($data);
                        $response = array("status"=>1, "message"=>"Employee working hours added successfully.", "data" => $insert); 
                    }else{
                        $response = array("status"=>0, "message"=>"Employee working hours not added, please try again!", "data" => NULL); 
                    }
                }
            } 
            else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }     
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response); 
    }
    
    public function getBusinessWorkingHours(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            $workData = $this->BusinessHoursModel->getWhere(["business_id" => $userData['id']])->getRowArray();
            if(!empty($workData)){
                $workData['timings'] = json_decode($workData['timings']);
                $response = array("status"=>1, "message"=>"Business Working Hours found.", "data" => $workData);
            }else{
                $response = array("status"=>0, "message"=>"Working Hours not found", "data" => NULL);
            }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function getEmployeeWorkingHours(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            $emp_id = $this->request->getVar('emp_id');
            $workData = $this->EmployeeHoursModel->getWhere(["emp_id" =>$emp_id])->getRowArray();
            
            if(!empty($workData)){
                $workData['timings'] = json_decode($workData['timings']);
                $response = array("status"=>1, "message"=>"Employee Working Hours found.", "data" => $workData);
            }else{
                $response = array("status"=>0, "message"=>"Working Hours not found", "data" => NULL);
            }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function getbusinessHours() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $workData = $this->BusinessWorkingHourModel->get_business_working_hours($userId);
                $columns = array_column($workData, 'id');
                array_multisort($columns, SORT_ASC, $workData);
                
                if(!empty($workData)) {
                    foreach($workData as $key => $breaks) {
                        $week_id = $breaks->id;
                        
                        //For breaks
                        $listBreaks = $this->BusinessBreakModel->getWhere(["week_id" => $week_id, "business_id" => $userData['id']])->getResultArray();
                        if(!empty($listBreaks)){
                            $workData[$key]->break_time=$listBreaks;
                        }else{
                            $workData[$key]->break_time=[];
                        }

                        if(!empty($listBreaks)){
                            $workData[$key]->default_break="false"; //Breaks added
                        }else{
                            $workData[$key]->default_break="true"; //Breaks not added
                        }
                        
                        //For working hours
                        $listHours = $this->AddBusinessWorkingHoursModel->getWhere(["week_id" => $week_id, "business_id" => $userData['id']])->getResultArray();
                        if(!empty($listHours)){
                            $workData[$key]->working_hours=$listHours;
                        }else{
                            $workData[$key]->working_hours=[];
                        }

                        if(!empty($listHours)){
                            $workData[$key]->default_working_hours="false"; //Working Hours added
                        }else{
                            $workData[$key]->default_working_hours="true"; //Working Hours not added
                        }
                    }
                    $response = array("status"=>1, "message"=>"Working Hours found.", "data" => $workData);
                } else {
                     $response = array("status"=>0, "message"=>"Working Hours not found", "data" => NULL);
                }
            } else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }     
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);     
    }
     
    public function assignBusinessIndustry() {
        $userId = $this->decodeToken();
        
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $userbusinessIndustry = $this->request->getVar('businessindustry');
                $assignBusiness = $this->AssignedBusinessCategoryModel->getWhere(["business_id" => $userId])->getRowArray();
                
                if(empty($assignBusiness)) {
                    $data = array('business_id' => $userId, 'bussiness_category_id' => $userbusinessIndustry);
                    $this->AssignedBusinessCategoryModel->save($data);

                    if($userData['is_step'] <= 3){
                        $udata = array('is_step' => '3');
                        $this->UserModel->update($userData['id'], $udata);
                    }
                    
                    $updatedassignBusiness = $this->AssignedBusinessCategoryModel->getWhere(["business_id" => $userId])->getRowArray();
                    $response = array("status"=>1, "message"=>"Successfully assigned business industry", "data" => $updatedassignBusiness); 
                } else {
                    $payload = array('bussiness_category_id' => $userbusinessIndustry);
                    $updateSuspendUser=$this->AssignedBusinessCategoryModel->where(["business_id"=>$userId])->set($payload)->update();
                    $updatedassignBusiness = $this->AssignedBusinessCategoryModel->getWhere(["business_id" => $userId])->getRowArray();
                    $response = array("status"=>1, "message"=>"Updated assigned business category", "data" => $updatedassignBusiness); 
                }    
            } else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }     
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);     
     } 
     
    public function getServices() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $businessCatData = $this->AssignedBusinessCategoryModel->getWhere(["business_id" => $userData['id']])->getRowArray();
               
                $services = $this->ServiceCategoryModel->getWhere(["business_id" => $userData['id'],"business_industry" => $businessCatData['bussiness_category_id']])->getResultArray();
                if(!empty($services)) {
                    $columns = array_column($services, 'service_name');
                    array_multisort($columns, SORT_ASC, $services);
                    $response = array("status"=>1, "message"=>"Services found", "data" => $services, "category" => $businessCatData['bussiness_category_id']); 
                } else {
                    $response = array("status"=>0, "message"=>"Services not found", "data" => [], "category" => $businessCatData['bussiness_category_id']); 
                } 
            } else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }     
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);      
    }

    public function assignService() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
    
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $userServices = $this->request->getVar('service');

                $services = explode(',', $userServices);

                $serviceData = $this->AssignedBusinessServiceModel->getWhere(["business_id" => $userData['id']])->getRowArray();

                if(!empty($serviceData)) {
                    $this->AssignedBusinessServiceModel->where(['business_id' => $userData['id']])->delete();

                    foreach($services as $serve) :
                        $data = array(
                            'business_id' => $userId,
                            'business_service_id' => $serve
                        );
    
                        $this->AssignedBusinessServiceModel->save($data);
                    endforeach;
    
                    $updatedUserData = $this->UserModel->get_single_userdata($userId);

                } else {
                    foreach($services as $serve) :
                        $data = array(
                            'business_id' => $userId,
                            'business_service_id' => $serve
                        );
    
                        $this->AssignedBusinessServiceModel->save($data);
                    endforeach;
    
                    if($userData['is_step'] <= 4){
                        $udata = array('is_step' => '4');
                        $this->UserModel->update($userData['id'], $udata);
                    }
                    
                    $updatedUserData = $this->UserModel->get_single_userdata($userId);

                }
                $response = array("status"=>1, "message"=>"Successfully assigned business services", "data" => $updatedUserData);
 
            } else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }     
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);     
    }
    
    public function assignsubService() {
        $userId = $this->decodeToken();
        
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $usersubServicesname = $this->request->getVar('subservicename');
                $usersubPrice = $this->request->getVar('subprice');
                $usersubDuration = $this->request->getVar('subduration');
                $usersubDesc = $this->request->getVar('subdesc');
                $usersubServId = $this->request->getVar('subserviceId');

                $data = array('sub_service_name' => $usersubServicesname, 'sub_service_price' => $usersubPrice, 'sub_service_duration' => $usersubDuration, 'sub_service_desc' => $usersubDesc, 'service_id' => $usersubServId, 'business_id' => $userId);
                $this->SubServiceModel->save($data);
                $lastinsertID = $this->SubServiceModel->getInsertID();
                $subServiceData = $this->SubServiceModel->getWhere(["id" => $lastinsertID])->getRowArray();

                if($userData['is_step'] <= 5){
                    $udata = array('is_step' => '5');
                    $this->UserModel->update($userData['id'], $udata);
                }
                
                $updatedUserData = $this->UserModel->get_single_userdata($userId);

                $response = array("status"=>1, "message"=>"Sub service added successfully", "data" => $updatedUserData); 
            } else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }     
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);     
    }

    public function addEmployee() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $business_id = $userData['id'];
                $file = $this->request->getFile('empimg');
                $userFirst = $this->request->getVar('firstname');
                $userLast = $this->request->getVar('lastname');
                $userEmail = $this->request->getVar('email');
                $userGender = $this->request->getVar('gender');
                $userTitle = $this->request->getVar('title');
                $userDesc = $this->request->getVar('desc');
                $userCountryCode = $this->request->getVar('country_code');
                $userPhoneNumber = $this->request->getVar('phone_number');
                $userPwd = "Welcome@Moten123";
                
                if( ($file != '') && (isset($file)) ) {
                    $ext = $file->getClientExtension();
                        
                    if( ($ext == "png") || ($ext == "jpg") || ($ext == "gif") || ($ext == "jpeg") ) {
                        $name = $file->getRandomName();
                        
                        $file->move('public/employeeImg', $name);
                        
                        $data = array('emp_img' => $name, 'emp_first_name' => $userFirst, 'emp_last_name' => $userLast, 'emp_email' => $userEmail, 'emp_password' => $userPwd, 'emp_gender' => $userGender, 'emp_title' => $userTitle, 'emp_desc' => $userDesc, 'business_id' => $userId ,'country_code' => $userCountryCode,'phone_number' => $userPhoneNumber);
                       
                    } else {
                        $data = array();
                        $response=array("status"=>0,"message"=>"Please upload jpg|png|jpeg|gif image format.");
                    }      
                } 
                else {
                    $data = array('emp_first_name' => $userFirst, 'emp_last_name' => $userLast, 'emp_email' => $userEmail, 'emp_password' => $userPwd, 'emp_gender' => $userGender, 'emp_title' => $userTitle, 'emp_desc' => $userDesc, 'business_id' => $userId,'country_code' => $userCountryCode,'phone_number' => $userPhoneNumber);
                }  
                
                $checkEmail = $this->EmployeeModel->checkEmpemailExist($userEmail);
                if($checkEmail == 0){
                    $checkEmpCount = $this->EmployeeModel->checkEmpExist($business_id);
                    $checkEmpCount++;
                    $data['emp_uid'] = 'EMP'.str_pad($checkEmpCount, 3, '0', STR_PAD_LEFT);
                    $this->EmployeeModel->save($data); 
                    $lastinsertID = $this->EmployeeModel->getInsertID();
                    $employeeData = $this->EmployeeModel->getWhere(["emp_id" => $lastinsertID])->getRowArray();
                    
                    /*$allweekDays = array('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun');
                    foreach($allweekDays as $key => $weekDay) :
                           
                            if($weekDay == 'Sun') {
                                $workData = [
                                            'day' => $weekDay,
                                            'opening_time' => '10:00',   //10:00
                                            'closing_time' => '18:00',   //18:00
                                            'from_break_time' => '13:00', //13:00
                                            'to_break_time' => '14:00',  //14:00
                                            'emp_id' => $employeeData['emp_id'],
                                            'work_status' => '1' //For closed day
                                        ]; 
                                $this->EmployeeWorkingHourModel->save($workData);
                            } else {
                                $workData = [
                                            'day' => $weekDay,
                                            'opening_time' => '10:00',
                                            'closing_time' => '18:00',
                                            'from_break_time' => '13:00',
                                            'to_break_time' => '14:00',
                                            'emp_id' => $employeeData['emp_id'],
                                            'work_status' => '0' //For open day
                                        ];
                                $this->EmployeeWorkingHourModel->save($workData);        
                            } 
                    endforeach;*/
                    
                    $timings = '[{"day":"Mon","opening_time":"10:00","closing_time":"18:00","from_break_time":"13:00","to_break_time":"14:00","work_status":"0"},{"day":"Tue","opening_time":"10:00","closing_time":"18:00","from_break_time":"13:00","to_break_time":"14:00","work_status":"0"},{"day":"Wed","opening_time":"10:00","closing_time":"18:00","from_break_time":"13:00","to_break_time":"14:00","work_status":"0"},{"day":"Thu","opening_time":"10:00","closing_time":"18:00","from_break_time":"13:00","to_break_time":"14:00","work_status":"0"},{"day":"Fri","opening_time":"10:00","closing_time":"18:00","from_break_time":"13:00","to_break_time":"14:00","work_status":"0"},{"day":"Sat","opening_time":"10:00","closing_time":"18:00","from_break_time":"13:00","to_break_time":"14:00","work_status":"0"},{"day":"Sun","opening_time":"10:00","closing_time":"18:00","from_break_time":"13:00","to_break_time":"14:00","work_status":"1"}]';
                    $created_at	= date('Y-m-d H:i:s');
                    
                    $hours_data = [
                        "emp_id" => $lastinsertID,
                        "timings"     => $timings,
                        "created_at"  => $created_at,
                    ];
                    $this->EmployeeHoursModel->save($hours_data);   
                      
                    if($userData['is_step'] <= 6){
                        $udata = array('is_step' => '6');
                        $this->UserModel->update($userData['id'], $udata);
                    }
                    $updatedUserData = $this->UserModel->get_single_userdata($userId);

                    $response = array("status"=>1, "message"=>"Employee added successfully", "data" => $updatedUserData, "employeeData" => $employeeData);
                }
                else{
                    $response = array("status"=>0, "message"=>"Email already exists. Please enter a different email address.", 'data' =>NULL);
                }
            } else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }       
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response);
    } 
    
    public function getbusinessServices() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $businessCatData = $this->AssignedBusinessCategoryModel->getWhere(["business_id" => $userData['id']])->getRowArray();
                
                $services = $this->AssignedBusinessServiceModel->getWhere(["business_id" => $userId])->getResultArray();
                if(!empty($services)) {
                    foreach($services as $serve) :
                        $businessService = $serve['business_service_id'];  
                        $serv = $this->ServiceCategoryModel->getWhere(["service_id" => $businessService])->getRowArray();
                        if(!empty($serv)) {
                            $allService[] = $serv;
                        }
                    endforeach;
                    
                    if(!empty($allService)) {
                        foreach($allService as $key=>$service) :
                           $serviceID = $service['service_id'];
                           $service_data = $this->SubServiceModel->getWhere(["service_id" => $serviceID, "business_id" => $userId])->getResultArray();
                           if(!empty($serviceID) && !empty($service_data)){
                               $allService[$key]['subservices'] = $service_data;
                           }
                        endforeach;
                        $response = array("status"=>1, "message"=>"Services found", "data" => $allService,"category" => $businessCatData['bussiness_category_id']);
                    }else{
                         $response = array("status"=>0, "message"=>"Services not found", "data" => NULL,"category" => $businessCatData['bussiness_category_id']);
                    } 
                }  
                else {
                    $response = array("status"=>0, "message"=>"Services not found", "data" => NULL,"category" => $businessCatData['bussiness_category_id']); 
                } 
            } else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }       
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);
    }
    
    public function socialRegister() {
        $userFirst = $this->request->getVar('firstname');
        $userLast = $this->request->getVar('lastname');
        $userEmail = $this->request->getVar('email');
        $userSocialId = $this->request->getVar('socialId');
        $userSocialType = $this->request->getVar('socialType');
        $deviceId = $this->request->getVar('devId');
        $deviceType = $this->request->getVar('devType');
        $deviceToken = $this->request->getVar('devToken');
        $userType = $this->request->getVar('type');
        $userPlan = $this->request->getVar('plan'); 
        
        if($userEmail) {
            $checkEmail = $this->UserModel->checkemailTypeExist($userEmail, $userType);

            if($checkEmail > 0) {
                //$response=array("status"=>0,"message"=>"E-mail already exist");
                $updateduserData = $this->UserModel->loggedInByEmail($userEmail, $userType);
                $userToken = $this->encodeToken($updateduserData);
                $response = array("status"=>1, "message"=>"Social login successfully", "data" => $updateduserData, "token" => $userToken);   
            } else {
                    //IF MOBILE NO. DOESN'T EXIST
                    $checkSocial = $this->UserModel->checksocialIdExist($userSocialId);

                    if($checkSocial > 0) {
                        $response=array("status"=>0,"message"=>"Social Id already exist");
                    } else {
                        $data = array(
                            'first_name' => $userFirst,
                            'last_name' => $userLast,
                            'email' => $userEmail,
                            'device_id' => $deviceId,
                            'device_type' => $deviceType,
                            'device_token' => $deviceToken,
                            'social_id' => $userSocialId,
                            'social_type' => $userSocialType, 
                            'user_type' => $userType,
                            'is_plan' => $userPlan
                        );
    
                        $result = $this->UserModel->save($data);
                        $lastinsertID = $this->UserModel->getInsertID();
    
                        if($result == 1) { 
                            $updateduserData = $this->UserModel->get_single_userdata($lastinsertID);
                            $userToken = $this->encodeToken($updateduserData);
                            if($userType == 2) {
                                $allweekDays = array('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun');
                                
                                foreach($allweekDays as $key => $weekDay) :

                                    if($weekDay == 'Sun') {
                                        $workData = [
                                                    'day' => $weekDay,
                                                    'opening_time' => '10:00',   //10:00
                                                    'closing_time' => '18:00',   //18:00
                                                    'from_break_time' => '13:00', //13:00
                                                    'to_break_time' => '14:00',  //14:00
                                                    'business_id' => $lastinsertID,
                                                    'work_status' => '1'
                                                ]; 
                                    } else {
                                        $workData = [
                                                    'day' => $weekDay,
                                                    'opening_time' => '10:00',
                                                    'closing_time' => '18:00',
                                                    'from_break_time' => '13:00',
                                                    'to_break_time' => '14:00',
                                                    'business_id' => $lastinsertID,
                                                    'work_status' => '0'
                                                ];
                                    }            
                                    $this->BusinessWorkingHourModel->save($workData);            
                                endforeach;
                            }    
                                $response = array("status"=>1, "message"=>"Social Registeration successfully", "data" => $updateduserData, "token" => $userToken);   
                        } else {
                            $response = array("status"=>0, "message"=>"Not Registered", "data" => NULL);
                        }     
                    }        
            }    
        } else {
            $response = array("status"=>3, "message"=>"Email not found", "data" => NULL);
        }  
            return $this->respond($response);
    }

    public function employeeLogin() {
        $userEmail = $this->request->getVar('email');
        $userPwd = $this->request->getVar('password');
        $deviceId = $this->request->getVar('devId');
        $deviceType = $this->request->getVar('devType');
        $deviceToken = $this->request->getVar('devToken');

        $userData = $this->EmployeeModel->getemployeeData($userEmail);
        
        if(!empty($userData)){
            if($userData['emp_active_status'] == 0){
                $pwd_verify = password_verify($userPwd, $userData['emp_password']);
    
                if(!$pwd_verify) {
                    $response=array("status"=>0,"message"=>"The password you have entered is incorrect. Please try again.");
                }else{ 
                    $data = array(
                        'emp_device_id' => $deviceId,
                        'emp_device_type' => $deviceType,
                        'emp_device_token' => $deviceToken
                        );
                    $this->EmployeeModel->update($userData['emp_id'], $data);
        
                    $updateduserData = $this->EmployeeModel->get_single_userdata($userData['emp_id']);
                    $userToken = $this->empencodeToken($updateduserData);
    
                    $response = array("status"=>1, "message"=>"Login data here", "data" => $updateduserData, "token" => $userToken);
                } 
           }else{
                $response = array("status"=>0, "message"=>"You have deactivated your account so, to continue you have to contact your Service administrator!", "data" => NULL);
           }
       }else {
            $response = array("status"=>0, "message"=>"User not found", "data" => NULL);
       }  
     return $this->respond($response);     
    }

    public function empgetProfile() {
        $userId = $this->empdecodeToken();

        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            $response = array("status"=>1, "message"=>"User data here", "data" => $userData);
        } else {
            $response = array("status"=>0, "message"=>"User not found", "data" => NULL);
        }  
            return $this->respond($response);
    }

    public function emplogout() {
        $userId = $this->empdecodeToken();
        
        $userData = $this->EmployeeModel->get_single_userdata($userId);

        if(!empty($userData)) { 
            $key = $this->getjwtKey();

            $iat = time();
            $nbf = $iat + 10;
            $exp = $iat + 15780000;
           
            $payload = array(
                "iss" => "The_claim",
                "aud" => "The_Aud",
                "sub" => "Subject of the JWT",
                "iat" => $iat,
                "id" => $userId,
            );

            $token = JWT::encode($payload, $key, 'HS256');

            $data=array(
                'emp_device_id' => '',
                'emp_device_type' => '',
                'emp_device_token' => ''
            );

            $result = $this->EmployeeModel->update($userId, $data);

            $updatedUserData = $this->EmployeeModel->get_single_userdata($userId);
           
            $response=array("status"=>1,"message"=>"Logout successful", "data" => $updatedUserData);
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);         
    }

    public function empforgotPassword() {
        $emailID = $this->request->getVar('email');

        $userData = $this->EmployeeModel->getemployeeData($emailID);

        if(!empty($userData)) {
            $random = substr(md5(time()), 0, 12);

            $data = array('email_code' => $random);
            $this->EmployeeModel->update($userData['emp_id'], $data);

            $encyrptEmail = base64_encode($emailID);
            $resetpwdLink = base_url() . "/API/Home/verifyEmail/?activation_code=" . $random . "&email=".$encyrptEmail;
            $data = array('link' => $resetpwdLink);
            $type = 7;

            $sentEmail = $this->sendGridEmail($emailID, $type, $data);

            if($sentEmail == 202) {
                $response=array("status"=>1,"message"=>"E-mail verification link sent you successfully on your e-mail");
            } else {
                $response = array("status"=>0, "message"=>"E-mail not sent");
            } 
        }  else {
            $response = array("status"=>0, "message"=>"Sorry, we can't find an account with this email address. Please try again or create a new account.", "data" => NULL);
        } 
            return $this->respond($response);        
    }

    public function verifyEmail() {
        // Status = 1 (E-mail Verified)
        // Status = 0 (E-mail not Verified)
        // moten://https://ankit.parastechnologies.in/moten/verify?email=parasdinesh8610@gmail.com&emailStatus=1
        $activation_token  = $this->request->getVar('activation_code');
        $email_id  = $this->request->getVar('email');

        if ( ! empty ( $email_id ) ) {
            $email = base64_decode( $email_id );
            $userData = $this->EmployeeModel->getWhere(["emp_email" => $email, "email_code" => $activation_token])->getRowArray();

            if(!empty($userData)) {
                $data = array('email_code' => '', 'emp_verify' => '1');
                $this->EmployeeModel->update($userData['emp_id'], $data);
                ?>
                    <script>
                    var userAgent = navigator.userAgent || navigator.vendor || window.opera;
                    function changeLink(applink) 
                    {
                        window.location.href=applink;
                    }
            
                    if( userAgent.match( /iPad/i ) || userAgent.match( /iPhone/i ) || userAgent.match( /iPod/i ) ) 
                    {
                        changeLink("EmpMoten://<?php echo base_url(); ?>/verify?email=<?php echo $email;?>&emailStatus=1");
                            setInterval(function () {
                                window.location.replace("https://apps.apple.com/us/app/google/id284815942");
                            }, 3000); 
                    } else if( userAgent.match( /Android/i ) ) {
                        changeLink("EmpMoten://<?php echo base_url(); ?>/verify?email=<?php echo $email;?>&emailStatus=1");

                            setInterval(function () {
                                window.location.replace("https://play.google.com/store/apps/dev?id=5700313618786177705");
                            }, 3000); 
                    } else {
                        changeLink("<?php echo base_url(); ?>/verify?email=<?php echo $email;?>&emailStatus=1");
                        setInterval(function () {
                            window.location.replace("https://www.google.com/");
                        }, 3000); 
                    }
                </script> 
                <?php
            } else {
                $data = array('email_code' => '');
                $this->EmployeeModel->update($userData['emp_id'], $data);
                $updateduserData = $this->EmployeeModel->getemployeeData($email);
                $status = $updateduserData['emp_verify'];
                ?>
                <script>
                var userAgent = navigator.userAgent || navigator.vendor || window.opera;
                function changeLink(applink) 
                {
                    window.location.href=applink;
                }
        
                if( userAgent.match( /iPad/i ) || userAgent.match( /iPhone/i ) || userAgent.match( /iPod/i ) ) 
                {
                    changeLink("EmpMoten://<?php echo base_url(); ?>/verify?email=<?php echo $email;?>&emailStatus=<?php echo $status; ?>");
                        setInterval(function () {
                            window.location.replace("https://apps.apple.com/us/app/google/id284815942");
                        }, 3000); 
                } else if( userAgent.match( /Android/i ) ) {
                    changeLink("EmpMoten://<?php echo base_url(); ?>/verify?email=<?php echo $email;?>&emailStatus=<?php echo $status; ?>");

                        setInterval(function () {
                            window.location.replace("https://play.google.com/store/apps/dev?id=5700313618786177705");
                        }, 3000); 
                } else {
                    changeLink("<?php echo base_url(); ?>/verify?email=<?php echo $email;?>&emailStatus=<?php echo $status; ?>");
                    setInterval(function () {
                        window.location.replace("https://www.google.com/");
                    }, 3000); 
                } 
            </script> 
            <?php 
            } 
        } else {
            $response = array("status"=>0, "message"=>"Not getting Email");
        } 
            //return $this->respond($response); 
           
    }

    public function empchangePassword() {
        $userId = $this->empdecodeToken();

        $userData = $this->EmployeeModel->get_single_userdata($userId);

        if(!empty($userData)) { 
            $currentPwd = $this->request->getVar('oldpwd');
            $newpassword = $this->request->getVar('newpwd');
            
            $pwd_verify = password_verify($currentPwd, $userData['emp_password']);

            if(!$pwd_verify) {
                $response=array("status"=>0,"message"=>"Old password is incorrect.");
            }  else { 
                $data = array('emp_password' => $newpassword);
                $result = $this->EmployeeModel->update($userData['emp_id'], $data);

                if($result == 1) {
                    $response=array("status"=>1,"message"=>"password changed successfully");
                } else {
                    $response=array("status"=>1,"message"=>"password not updated");
                }
            }    
        } else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);    
    }

    public function emppostSupport() {
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);

        if(!empty($userData)) { 
            $userName = $this->request->getVar('name');
            $userEmail = $this->request->getVar('email');
            $userConcern = $this->request->getVar('concern');
            
            $data = array('name' => $userName, 'email' => $userEmail, 'user_id' => $userId, 'context' => $userConcern);

            $postedUser = $userData['emp_first_name']." ".$userData['emp_last_name'];

            $maildata = array('name' => $userName, 'email' => $userEmail, 'posted_by' => $postedUser, 'context' => $userConcern);

            $userEmail2 = "parasdinesh8610@gmail.com";

            $type = 8;
           
            $sentEmail = $this->sendGridEmail($userEmail2, $type, $maildata);

            if($sentEmail == 202) {
                $insert = $this->SupportModel->save($data);
                $response = array("status"=>1, "message"=>"Your query has sent successfully.");
            } else {
                $response = array("status"=>0, "message"=>"Your query has not been sent!");
            } 
        } else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);    
    }

    public function empresetPassword() {
        $emailID = $this->request->getVar('email');
        $currentPwd = $this->request->getVar('pwd');

        $userData = $this->EmployeeModel->getemployeeData($emailID);
        if(!empty($userData)) { 
            $data = array('emp_password' => $currentPwd);
            $result = $this->EmployeeModel->update($userData['emp_id'], $data);

            if($result == 1) {
                $response=array("status"=>1,"message"=>"password changed successfully");
            } else {
                $response=array("status"=>1,"message"=>"password not updated");
            }
        } else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response);    
    }
    
    public function managePaymentInfo(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $payment_type = $this->request->getVar('payment_type'); //0=InShop,1=OnlinePay,2=Both
            
            if(!empty($payment_type)){
               $data = ['business_id'=>$userData['id'],'payment_type'=>$payment_type]; 
            }else{
               $data = ['business_id'=>$userData['id'],'payment_type'=>"0"];
            }
            
            $get_payment_type  = $this->BusinessPaymentTypeModel->getWhere(['business_id'=>$userData['id']])->getRowArray();
            if(!empty($get_payment_type)){
                $this->BusinessPaymentTypeModel->update($get_payment_type['id'],$data);
            }else{
                $this->BusinessPaymentTypeModel->insert($data);
            }
            
            $get = $this->BusinessPaymentTypeModel->getWhere(['business_id'=>$userData['id']])->getRowArray();
            $response = array("status"=>1, "message"=>"Payment type added successfully.", "data" => $get);
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        }
        return $this->respond($response);    
    }
    
    public function getBusinessPaymentType(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $get_payment_type  = $this->BusinessPaymentTypeModel->getWhere(['business_id'=>$userData['id']])->getRowArray();
            if(!empty($get_payment_type)){
                $response = array("status"=>1, "message"=>"Payment info found.", "data" => $get_payment_type);
            }else{
                $response = array("status"=>1, "message"=>"Payment info not found!", "data" => NULL);
            }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        }
        return $this->respond($response);    
    }
    
    public function distance(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        $user_id = $userData['id'];
        $business_id = $this->request->getVar('business_id');
        
        echo $this->calculateDistance($user_id,$business_id);
    }
    
    public function calculateDistance($user_id,$business_id){
        $get_lat_long_user = $this->UserModel->getWhere(['id'=>$user_id])->getRowArray(); //Get User Lat. & Long.
        $lat1 = $get_lat_long_user['latitude'];
        $lon1 = $get_lat_long_user['longitude'];
        
        $get_lat_long_business = $this->BusinessDetailModel->getWhere(['business_id'=>$business_id])->getRowArray(); //Get Service Lat. & Long.
        $lat2 = $get_lat_long_business['business_latitude'];
        $lon2 = $get_lat_long_business['business_longitude'];
        
        if(empty($lat1) || empty($lon1) || empty($lat2) || empty($lon2)){
            $distance = "";
        }else{
            $distance = round((((acos(sin(($lat1*pi()/180)) * sin(($lat2*pi()/180))+cos(($lat1*pi()/180)) * cos(($lat2*pi()/180)) * cos((($lon1- $lon2)*pi()/180))))*180/pi())*60*1.1515*1.609344),0);
        }
        
        return $string = (string)$distance;
    }
    
    public function ratingCount(){
        $id = $this->request->getVar('id');
        $type = $this->request->getVar('type');
        
        echo $this->calculateRating($id,$type);
    }
    
    public function calculateRating($id,$type){
        $ratings_count = $this->RateReviewBusinessEmployeeModel->get_ratings_count($id,$type);
        
        if($type == "0"){ //Business Rating
            $get_bus_rating = $this->RateReviewBusinessEmployeeModel->getWhere(['bus_emp_id'=>$id,'type'=>$type])->getResultArray(); 
            $period_array = array();
            
            foreach($get_bus_rating as $arr){
                $period_array[] = $arr['rating'];
            }
            
            $total_rating_array = array_sum($period_array);
            
            if($ratings_count != "0"){
                $avg = $total_rating_array/$ratings_count;
                $rating = round($avg,1);
            }else{
                $rating = "0";
            }
        }else{ //Employee Rating 
            $get_emp_rating = $this->RateReviewBusinessEmployeeModel->getWhere(['bus_emp_id'=>$id,'type'=>$type])->getResultArray(); 
            $period_array = array();
            
            foreach($get_emp_rating as $arr){
                $period_array[] = $arr['rating'];
            }
            
            $total_rating_array = array_sum($period_array);
            
            if($ratings_count != "0"){
                $avg = $total_rating_array/$ratings_count;
                $rating = round($avg,1);
            }else{
                $rating = "0";
            }
        }
        
        return $string = (string)$rating;
    }
    
    public function reviewCount(){
        $id = $this->request->getVar('id');
        $type = $this->request->getVar('type');
        
        echo $this->calculateReview($id,$type);
    }
    
    public function calculateReview($id,$type){
        if($type == "0"){ //Business Review
            $get_bus_review_count = $this->RateReviewBusinessEmployeeModel->get_business_review_count($id,$type);
            if($get_bus_review_count != "0"){
                $review = $get_bus_review_count;
            }else{
                $review = "0";
            }
        }else{ //Employee Review 
            $get_emp_review_count = $this->RateReviewBusinessEmployeeModel->get_emp_review_count($id,$type); 
            if($get_emp_review_count != "0"){
                $review = $get_emp_review_count;
            }else{
                $review = "0";
            }
        }
        
        return $string = (string)$review;
    }
    
    public function chooseStaff(){
        $business_id = $this->request->getVar('business_id');
        $sub_service_id = $this->request->getVar('sub_service_id');
        
        if(empty($sub_service_id)){
            $get_business_employees = $this->EmployeeModel->getWhere(['business_id' => $business_id])->getResultArray();
            if(!empty($get_business_employees)){
                foreach($get_business_employees as $emps => $empId){
                    $id = $empId['emp_id']; 
                    $type = '1';
                    
                    $get_business_employees[$emps]['emp_rating'] = $this->calculateRating($id,$type);
                }
                $columns = array_column($get_business_employees, 'emp_rating');
                array_multisort($columns, SORT_DESC, $get_business_employees);
                $response=array("status"=>1,"message"=>"Staff found.", "data" => $get_business_employees);
            }else{
                $response=array("status"=>0,"message"=>"Staff not found!","data"=>NULL);
            }
        }else{
            $services = explode(',', $sub_service_id);
                $serviceData = $this->SubServiceModel->whereIn('id', $services)->getWhere(["business_id" => $business_id])->getResultArray();
                if(!empty($serviceData)){
                        $emp = $this->EmployeeSubServiceModel->get_choose_staff_data($services);
                        foreach($emp as $k => $val){
                            $id = $val['emp_id']; 
                            $type = '1';
                            
                            $emp[$k]['emp_rating'] = $this->calculateRating($id,$type);
                        }
                        $columns = array_column($emp, 'emp_rating');
                        array_multisort($columns, SORT_DESC, $emp);
                        
                        $temp = array_unique(array_column($emp, 'emp_id'));
                        $unique_arr = array_intersect_key($emp, $temp);
                        $new_array = array_values($unique_arr);
                        
                        if (!empty($emp)) {
                            $response=array("status"=>1,"message"=>"Staff found.", "data" => $new_array);
                        }else{
                            $response=array("status"=>0,"message"=>"Staff not found.", "data" => NULL);
                        }
                }
                else{
                    $response=array("status"=>0,"message"=>"Service not found.", "data" => NULL);
                }
        }
        return $this->respond($response);
    }
    
    public function chooseServices(){
        $emp_id = $this->request->getVar('emp_id');
        
        if(!empty($emp_id)){
            $get_services = $this->EmployeeServiceModel->empServices($emp_id);
                if(!empty($get_services)){
                    foreach($get_services as $key => $services){
                        $service_id = $services['service_id'];
                        
                        $business_sub_services = $this->SubServiceModel->getWhere(["service_id" => $service_id])->getResultArray();
                        $emp_sub_services = array();
                        foreach($business_sub_services as $sub_services){
                            $sub_service_id = $sub_services['id'];
                            
                            $emp_services = $this->EmployeeSubServiceModel->emp_service_sub_service($emp_id,$sub_service_id);
                            if ( !empty ($emp_services) ) {
                                $emp_sub_services[] = $emp_services;
                                if(!empty($emp_sub_services)){
                                    $get_services[$key]['sub_services'] = $emp_sub_services;
                                }else{
                                    $get_services[$key]['sub_services'] = [];
                                }
                            }
                        }
                    }
                    $response=array("status"=>1,"message"=>"Services found.", "data" => $get_services);
                }else{
                    $response=array("status"=>0,"message"=>"Services not found.", "data" => NULL);
                }
        }else{
            $response=array("status"=>0,"message"=>"Staff not selected.", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function chooseDate(){
        $business_id = $this->request->getVar('business_id');
        $date = $this->request->getVar('date'); //yyyy-mm-dd
        
        $day = date("D",strtotime($date)); 
        $business_schedule = $this->BusinessHoursModel->getWhere(["business_id" => $business_id])->getRowArray();
        $timings = $business_schedule['timings'];
        $obj = json_decode($timings);
        
        if(!empty($date)){
            if(!empty($obj)){
            foreach($obj as $key => $value){
               if( $day == $value->day ){
                   $response=array("status"=>1,"message"=>"Working hours found.", "data" =>$value);
                   break;
               }
            }
            }else{
                $response=array("status"=>0,"message"=>"Working hours not found!", "data" => NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"Please select a date first!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function checkEmpTimeAvailibilty(){
        $business_id = $this->request->getVar('business_id');
        $date = $this->request->getVar('date');
        $emp_id = $this->request->getVar('emp_id');
        $time = time(); 
    	$current_date = date("Y-m-d",$time);
        $time = $this->request->getVar('time');
        
        if(!empty($time)){
            $check_time_avaibility = $this->AddBookingModel->get_checked_booking_time($business_id,$time,$emp_id,$date);
            if(!empty($check_time_avaibility)){
                foreach($check_time_avaibility as $key => $value){
                    if( $value->booking_time == $time ){
                       $response=array("status"=>0,"message"=>"Please select a different time!");
                    }else{
                        $response=array("status"=>1,"message"=>"Booking time selected.");
                    }
                }
            }else{
                $response=array("status"=>1,"message"=>"Booking time selected.");
            }
        }else{
            $response=array("status"=>0,"message"=>"Please select a time first!");
        }
        return $this->respond($response);
    }
    
    public function staffNextAvailibleAppointment(){
        $emp_id = $this->request->getVar('emp_id');
        $current_date = date("Y-m-d",strtotime('now'));
        
        if(!empty($emp_id)){
            $get_staff = $this->AddBookingModel->get_staff_next_available_appointment_date($emp_id);
            if(!empty($get_staff)){
               foreach($get_staff as $key => $value){
                   if( $value->booking_date > $current_date ){
                       $response=array("status"=>1,"message"=>"Next available appointment date found.", "data" =>$value->booking_date);
                       break;
                   }
               }
            }else{
                 $response=array("status"=>1,"message"=>"Next available appointment date found.", "data" =>$current_date);
            }
        }else{
            $response=array("status"=>1,"message"=>"Please select a staff!", "data" =>NULL);
        }
		return $this->respond($response);
    }
    
    public function updateCouponStatus(){
        $get_expired_coupons = $this->AddCouponModel->get_expired_coupons();
        
        if(!empty($get_expired_coupons)){
            $data = ['status'=>'0'];
            foreach($get_expired_coupons as $coupons){
                $coupons->id;
                $update_coupon_status = $this->AddCouponModel->update($coupons->id,$data);
                
                if(!empty($update_coupon_status)){
                    $response=array("status"=>1,"message"=>"Coupon expired.", "data" => $update_coupon_status);
                }else{
                    $response=array("status"=>0,"message"=>"Coupon not expired!", "data" => NULL);
                }
            }
        }else{
            $response=array("status"=>0,"message"=>"No expired coupons found!", "data" => NULL);
        }
    }
    
    public function validateDiscountCode(){
        $business_id = $this->request->getVar('business_id');
        $discount_code = $this->request->getVar('discount_code');
        
        $check_coupon_existence = $this->AddCouponModel->getWhere(['business_id'=>$business_id,'discount_code'=>$discount_code,'status'=>'1'])->getRowArray();
        if(!empty($check_coupon_existence)){
           $response=array("status"=>1,"message"=>"Coupon applied successfully.", "data" =>$check_coupon_existence);
        }else{
           $response=array("status"=>0,"message"=>"Coupon code is Invalid. Please enter a valid coupon code.", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function chooseDateEmp(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $emp_id = $userData['emp_id'];
            $date = $this->request->getVar('date'); //yyyy-mm-dd
            
            $day = date("D",strtotime($date)); 
            $emp_schedule = $this->EmployeeHoursModel->getWhere(["emp_id" => $emp_id])->getRowArray();
            $timings = $emp_schedule['timings'];
            $obj = json_decode($timings);
            
            if(!empty($date)){
                if(!empty($obj)){
                    foreach($obj as $key => $value){
                       if( $day == $value->day ){
                           $response=array("status"=>1,"message"=>"Working hours found.", "data" =>$value);
                           break;
                       }
                    }
                }else{
                    $response=array("status"=>0,"message"=>"Working hours not found!", "data" => NULL);
                }
            }else{
                $response=array("status"=>0,"message"=>"Please select a date first!", "data" => NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        
        return $this->respond($response);
    }
    
    public function checkTimeAvailibilty(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $emp_id = $userData['emp_id'];
            $date = $this->request->getVar('date');
            $time = time(); 
        	$current_date = date("Y-m-d",$time);
            $time = $this->request->getVar('time');
            
            if(!empty($time)){
                $check_time_avaibility = $this->AddBookingModel->get_checked_booking_time_emp($time,$emp_id,$date);
                if(!empty($check_time_avaibility)){
                    foreach($check_time_avaibility as $key => $value){
                        if( $value->booking_time == $time ){
                           $response=array("status"=>0,"message"=>"Please select a different time!");
                        }else{
                            $response=array("status"=>1,"message"=>"Booking time selected.");
                        }
                    }
                }else{
                    $response=array("status"=>1,"message"=>"Booking time selected.");
                }
            }else{
                $response=array("status"=>0,"message"=>"Please select a time first!");
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function get_stripe_secret_key(){
        return 'sk_test_51MdmOlJJAF7tzFRKLM6IGH7mviZjTXPm76J9lH2m9ua56Q8RQ7WiDdaPQTxGOos4TkU1pLbcu8ZZujKy0TL86i6z00C6KmbA3i';
    }
    
    public function createCharge(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $user_name = $userData['first_name'];
            $user_email = $userData['email'];
            date_default_timezone_set('UTC');
            $utcDateTime = date('Y-m-d H:i:s');
            $utcOnlyDate = date('Y-m-d');
            
            $booking_id = $this->request->getVar('booking_id');
            $total_amount = $this->request->getVar('amount');
            $card_id = $this->request->getVar('card_id');
            
            //Stripe Secret Key
            $stripesecretKey = $this->get_stripe_secret_key();
            $stripe = new \Stripe\StripeClient($stripesecretKey);
            
            /*$token  = $stripe->tokens->create([
                'card' => [
                    'number'    => '4242 4242 4242 4242',
                    'exp_month' => '12',
                    'exp_year'  => '25',
                    'cvc'       => '789',
                ]
            ]);*/
            
            //Create Customer
            $customer = $stripe->customers->create([
                'email' => $user_email,
                'name' => $user_name,
            ]);
            
            //Charge Customer
            $process_payment = $stripe->paymentIntents->create([
                'amount' => 100 * $total_amount,
                'currency' => 'USD',
                'payment_method_types' => ['card'],
                'customer' => $customer->id,
                'confirmation_method' => 'manual',
                'confirm' => true,
                'payment_method_data' => [
                    'type' => 'card',
                    'card' => [
                        'token' => $this->request->getVar('stripeToken'),
                    ]
                ],
                "description" => "Payment for booking ID: " . $booking_id,
            ]);
            
            //Check Payment Status
            if(!empty($process_payment->id)){
                 $get_card_number = $this->CardModel->getWhere(['id'=>$card_id])->getRowArray(); //Get User Card Number
                 $get_business_id = $this->AddBookingModel->getWhere(['id'=>$booking_id])->getRowArray(); //Get User Business ID
                 
                // Insert transaction details
                $transactions       = array( 
                    'transaction_id' => $process_payment->id,
                    'source'        => 'stripe', 
                    'amount'        => $total_amount,
                    'user_id'       => $userData['id'], 
                    'booking_id'    => $booking_id, 
                    'pay_for'       => 'booking',
                    'created_at'    => $utcDateTime,
                    'payment_method_type' => $process_payment->payment_method_types,
                    'user_name'     => $user_name,
                    'user_email' => $user_email,
                    'card_number' => $get_card_number['card_number'],
                    'payment_status' => 'paid',
                    'business_id'    => $get_business_id['business_id'],
                    'payment_date'   => $utcOnlyDate,
                    'emp_id'         => $get_business_id['emp_id']
                );
                $this->PaymentInfoModel->insert($transactions);
                $response=array("status"=>1,"message"=>"Payment done sucessfully.", "data" =>$process_payment);
            }else{
                 $response=array("status"=>0,"message"=>"Payment failed, please try again!", "data" =>NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function userBookingReceipts(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
		if(!empty($userData)){
		    $user_id = $userData['id'];
		    
		    $get_bookings_receipts = $this->PaymentInfoModel->getWhere(['user_id'=>$user_id])->getResultArray();
		    if(!empty($get_bookings_receipts)){
		        foreach($get_bookings_receipts as $key => $receipts){
		            $booking_id = $receipts['booking_id'];
		            
		            $get_business_name = $this->AddBookingModel->get_receipt_booking_business_name($booking_id);
		            if(!empty($booking_id)){
		                $string_version = implode(',', $get_business_name);
		                $get_bookings_receipts[$key]['business_name'] = $string_version;
		            }else{
		                $get_bookings_receipts[$key]['business_name'] = "";
		            }
		        } 
		        $response=array("status"=>1,"message"=>"Receipts found.", "data" =>$get_bookings_receipts);
		    }else{
		        $response=array("status"=>0,"message"=>"No receipts found!", "data" =>NULL);
		    }
		}else{
		    $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
		}
		return $this->respond($response);
    }
    
    public function userBookingReceiptDetails(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
		if(!empty($userData)){
		    $user_id= $userData['id'];
		    $receipt = $this->request->getVar('id');
		    
		    $get_receipt_details = $this->PaymentInfoModel->getWhere(['id'=>$receipt,'user_id'=>$user_id])->getRowArray();
		    if(!empty($get_receipt_details)){
		            $booking_id = $get_receipt_details['booking_id'];
		            $user_id = $get_receipt_details['user_id'];
		            
		            $get_business_id = $this->AddBookingModel->getWhere(['id'=>$booking_id])->getRowArray();
		            $business_id = $get_business_id['business_id'];
		            
		            $get_business_img = $this->AddBookingModel->get_receipt_booking_business_img($booking_id);
		            if(!empty($get_business_img)){
		                $convert = implode(',',$get_business_img);
		                $get_receipt_details['business_img'] = $convert;
		            }else{
                        $get_receipt_details['business_img'] = "";
		            } 
		            
		            $get_business_name = $this->AddBookingModel->get_receipt_booking_business_dtl($booking_id);
		            if(!empty($get_business_name)){
		                $get_receipt_details['business_dtl'] = $get_business_name;
		            }else{
		                $default = array (
                            "business_name" => "",
                            "business_address_1" => "",
                            "business_address_2" => "",
                            "business_city" => "",
                        );
                        $get_receipt_details['business_dtl'] = $default;
		            } 
		            
		            $get_receipt_details['distance'] = $this->calculateDistance($user_id,$business_id);
		            
		            $get_booking_services = $this->BookingsServicesModel->get_receipt_booking_services($booking_id);
		            if(!empty($get_booking_services)){
		                $get_receipt_details['services'] = $get_booking_services;
		            }else{
                        $default = array (
                            "sub_service_name" => "",
                            "sub_service_price" => "",
                        );
                        $get_receipt_details['services'] = $default;
		            } 
		            
		            $sum=0;
		            foreach($get_booking_services as $keys => $services_total){
		                $service_total = $services_total['sub_service_price'];
		                $sum=$sum+$service_total;
		                $string = (string)$sum;
		            }
		            if(!empty($get_booking_services)){
		                $get_receipt_details['service_total'] = $string;
		            }else{
		                $get_receipt_details['service_total'] = '';
		            }
		            
		            $get_booking_tip = $this->AddBookingModel->get_booking_tip($booking_id);
		            if(!empty($get_booking_tip)){
		                $convert = implode(',',$get_booking_tip);
		                $get_receipt_details['tip'] = $convert;
		            }else{
                        $get_receipt_details['tip'] = "";
		            } 
		            
		            $get_booking_tax = $this->AddBookingModel->get_booking_tax($booking_id);
		            if(!empty($get_booking_tax)){
		                $convert = implode(',',$get_booking_tax);
		                $get_receipt_details['tax'] = $convert;
		            }else{
                        $get_receipt_details['tax'] = "";
		            } 
		            
		            $response=array("status"=>1,"message"=>"Receipts details found.", "data" =>$get_receipt_details);
		    }else{
		        $response=array("status"=>0,"message"=>"Receipt details not found!", "data" => NULL);
		    }
		}else{
		    $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
		}
		return $this->respond($response);
    }
    
    public function userBookApppointment(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
		if(!empty($userData)){
		    $user_id= $userData['id'];
		    $emailID= $userData['email'];
		    $username= $userData['first_name'];
		    $business_id = $this->request->getVar('business_id');
		    $emp_id = $this->request->getVar('emp_id');
		    $booking_date = $this->request->getVar('booking_date');
		    $booking_timestamp = strtotime($booking_date);
		    $booking_time = $this->request->getVar('booking_time');
    		$time = time(); 
    		$current_date = date("Y-m-d",$time);
    		$status = '0'; //0=Open
    		$booking_tip = $this->request->getVar('booking_tip');
    		$booking_tax = $this->request->getVar('tax');
    		$booking_note = $this->request->getVar('booking_note');
    		$booking_discount_code = $this->request->getVar('booking_discount_code');
    		$created_at	= date('Y-m-d H:i:s');
    		$type = "0";
    		$payment_type = $this->request->getVar('payment_type'); //0=In-Shop,1=Online
    		$repeat_time = $this->request->getVar('repeat_time');
    		$duration = $this->request->getVar('duration'); //days,weeks,months
    		
    		//Notification data start
    		/*$NotificationType = 1;
    		
	        date_default_timezone_set('UTC');
	        $utcDate = date('Y-m-d H:i:s');*/
	        //Notification data end
    	
    		if($booking_timestamp >= strtotime($current_date)){
    		    if(empty($repeat_time) || empty($duration)){
    		        if($emp_id == 0){ //Any staff start
        		    $assign_staff = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'status'=>$status])->getResultArray();
        		    if(!empty($assign_staff)){
        		         $staffs = $assign_staff;
        		    }else{
        		         $staffs = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'booking_date >='=>$current_date])->getResultArray();
        		    }
    		     
    		        $staff_id = array();
    		        foreach($staffs as $staff){
    		            $staff_ids[] = $staff['emp_id'];
    		            
    		            $get_free_staffs = $this->EmployeeModel->get_free_staffs($staff_ids,$business_id);
    		            if(!empty($get_free_staffs)){
    		                foreach($get_free_staffs as $getsid){
    		                    $data = [
                            		    'user_id'	    => $user_id,
                            			'emp_id'	    => $getsid['emp_id'],
                            			'booking_date'	=> $booking_date,
                            			'booking_time'	=> $booking_time,
                            			'created_at'	=> $created_at,
                            			'status'        => $status,
                            			'business_id'   => $business_id,
                            			'tip'           => $booking_tip,
                            			'note'          => $booking_note,
                            			'discount_code' => $booking_discount_code,
                            			'type'          => $type,
                            			'tax'           => $booking_tax,
                            			'payment_type'  => $payment_type
                        		];
                        		break;
    		                }
    		            }else{
    		                if($staff['booking_time'] != $booking_time){
        		                $data = [
                            		    'user_id'	    => $user_id,
                            			'emp_id'	    => $staff['emp_id'],
                            			'booking_date'	=> $booking_date,
                            			'booking_time'	=> $booking_time,
                            			'created_at'	=> $created_at,
                            			'status'        => $status,
                            			'business_id'   => $business_id,
                            			'tip'           => $booking_tip,
                            			'note'          => $booking_note,
                            			'discount_code' => $booking_discount_code,
                            			'type'          => $type,
                            			'tax'           => $booking_tax,
                            			'payment_type'  => $payment_type
                        		]; 
    		                }
    		           }
    		        }   
        		   } //Any staff end
        		   else{  
                        $data = [
                    		    'user_id'	    => $user_id,
                    			'emp_id'	    => $emp_id,
                    			'booking_date'	=> $booking_date,
                    			'booking_time'	=> $booking_time,
                    			'created_at'	=> $created_at,
                    			'status'        => $status,
                    			'business_id'   => $business_id,
                    			'tip'           => $booking_tip,
                    			'note'          => $booking_note,
                    			'discount_code' => $booking_discount_code,
                    			'type'          => $type,
                    			'tax'           => $booking_tax,
                    			'payment_type'  => $payment_type
                		]; 
        		  }
    		    }else{ //Set recurring start
    		        if($duration == "days"){
    		           $date = strtotime("+".$repeat_time." days", strtotime($booking_date)); //Adding day to a date
    		        }elseif($duration == "weeks"){
    		           $date = strtotime("+".$repeat_time." weeks", strtotime($booking_date)); //Adding week to a date 
    		        }else{
    		           $date = strtotime("+".$repeat_time." months", strtotime($booking_date)); //Adding month to a date
    		        }
    		        
    		        $booking_new_date = date("Y-m-d", $date);
    		        
    		        if($payment_type == "0"){
    		            $set_recurring_status = "";
    		        }else{
    		            $set_recurring_status = "0";
    		        }
    		        
    		        if($emp_id == 0){ //Any staff start
        		    $assign_staff = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'status'=>$status])->getResultArray();
        		     if(!empty($assign_staff)){
        		         $staffs = $assign_staff;
        		     }else{
        		         $staffs = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'booking_date >='=>$current_date])->getResultArray();
        		     }
    		     
    		        $staff_id = array();
    		        foreach($staffs as $staff){
    		            $staff_ids[] = $staff['emp_id'];
    		            
    		            $get_free_staffs = $this->EmployeeModel->get_free_staffs($staff_ids,$business_id);
    		            if(!empty($get_free_staffs)){
    		                foreach($get_free_staffs as $getsid){
    		                    $data = [
                            		    'user_id'	    => $user_id,
                            			'emp_id'	    => $getsid['emp_id'],
                            			'booking_date'	=> $booking_new_date,
                            			'booking_time'	=> $booking_time,
                            			'created_at'	=> $created_at,
                            			'status'        => $status,
                            			'business_id'   => $business_id,
                            			'tip'           => $booking_tip,
                            			'note'          => $booking_note,
                            			'discount_code' => $booking_discount_code,
                            			'type'          => $type,
                            			'tax'           => $booking_tax,
                            			'payment_type'  => $payment_type,
                            			'set_recurring_status' => $set_recurring_status
                        		];
                        		break;
    		                }
    		            }else{
    		                if($staff['booking_time'] != $booking_time){
        		                $data = [
                            		    'user_id'	    => $user_id,
                            			'emp_id'	    => $staff['emp_id'],
                            			'booking_date'	=> $booking_new_date,
                            			'booking_time'	=> $booking_time,
                            			'created_at'	=> $created_at,
                            			'status'        => $status,
                            			'business_id'   => $business_id,
                            			'tip'           => $booking_tip,
                            			'note'          => $booking_note,
                            			'discount_code' => $booking_discount_code,
                            			'type'          => $type,
                            			'tax'           => $booking_tax,
                            			'payment_type'  => $payment_type,
                            			'set_recurring_status' => $set_recurring_status
                        		]; 
    		                }
    		           }
    		        }   
        		   } //Any staff end
        		   else{  
                        $data = [
                    		    'user_id'	    => $user_id,
                    			'emp_id'	    => $emp_id,
                    			'booking_date'	=> $booking_new_date,
                    			'booking_time'	=> $booking_time,
                    			'created_at'	=> $created_at,
                    			'status'        => $status,
                    			'business_id'   => $business_id,
                    			'tip'           => $booking_tip,
                    			'note'          => $booking_note,
                    			'discount_code' => $booking_discount_code,
                    			'type'          => $type,
                    			'tax'           => $booking_tax,
                    			'payment_type'  => $payment_type,
                    			'set_recurring_status' => $set_recurring_status
                		]; 
        		  }
    		    } //Set recurring end
    		 
		      $result = $this->AddBookingModel->insert($data);
		      $last_inserted_id = $this->AddBookingModel->insertID();
		      if(!empty($last_inserted_id)) {
		        $sub_service_id = array();
		        $sub_service_id = (explode(",",$this->request->getVar('sub_service_id')));
		        foreach ($sub_service_id as $row) { 
        		        $get_sub_nam = $this->SubServiceModel->get_sub_service_name($row);
                        $sub_services['sub_services'] = $row;
        		        $data = [
                		    'sub_service_id' => $sub_services,
                			'booking_id'	 => $last_inserted_id,
                			'user_id'        => $user_id,
                			'sub_service_name' => $get_sub_nam['sub_service_name'],
                		];
        		        $upresult = $this->BookingsServicesModel->insert($data);
                } 
                
                $recurring_data = ['booking_id'=>$last_inserted_id,'repeat_time'=>$repeat_time,'duration'=>$duration,'booking_previous_date'=>$booking_date,'user_id'=>$user_id];
                $insert_recurring_booking_data = $this->SetRecurringBookingModel->insert($recurring_data);
                
                /*$title = "Appointment";
	            $msg = $userData['first_name']." ".$userData['last_name'] ." booked a appointment with you";
	            $notifyData = array('senderId' => $user_id, 'receiverId' => $business_id, 'notification_title' => $title, 'notification_msg' => $msg, 'notification_type' => $NotificationType, 'created_at' => $utcDate);
	            $resp = $this->sendNotification($NotificationType, $notifyData);*/
	            
                $get_booking_data = $this->AddBookingModel->getWhere(['id'=>$last_inserted_id])->getRowArray();
                
                $business_dtls = $this->BusinessDetailModel->getWhere(['business_id'=>$business_id])->getRowArray();
                if(!empty($business_dtls)){
                    $get_booking_data['business_details'] = $business_dtls;
                }else{
                    $default = array (
                            "id" => "",
                            "business_name" => "",
                            "business_address_1" => "",
                            "business_address_2" => "",
                            "business_city" => "",
                            "business_province" => "",
                            "business_postal_code" => "",
                            "business_country_code" => "",
                            "business_phone" => "",
                            "business_id" => "",
                            "business_latitude" => "",
                            "business_longitude" => ""
                    );
                    $get_upcoming_bookings['business_details'] = $default;
                }
                $response=array("status"=>1,"message"=>"Booking added successfully.", "data" => $get_booking_data);
             }else{
                $response=array("status"=>0,"message"=>"Booking not added, please try again!");
             }
		  }else{
		    $response=array("status"=>0,"message"=>"Booking date must be greater than or equal to current date!", "data" => NULL);
		  }
		}else{
		    $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
		}
		return $this->respond($response);
    }
    
    public function send_email_reminder(){ //Send email reminder for recurring booking payment
        $set_recurring_status = $this->AddBookingModel->getWhere(['set_recurring_status'=>"0"])->getResultArray();
        foreach($set_recurring_status as $status){
                $user_id = $status['user_id']; 
                
                $get_user_data = $this->AddBookingModel->get_booked_user_data($user_id);
                foreach($get_user_data as $users){
                    $emailID = $users->email;
                    $booking_id = $users->id;
                    
                    if(!empty($emailID)){
                        $encyrptEmail = base64_encode($emailID);
                        $paymentLink = base_url() . "/API/Home/set_recurring_email/?email=" . $encyrptEmail. "&booking_id=".$booking_id. "&user_id=".$user_id;
                        $data = array('link' => $paymentLink,'username'=>$users->first_name,'booking_id'=>$booking_id,'booking_date'=>$users->booking_date);
                        $type = 9; 
                
                        $sentEmail = $this->sendGridEmail($emailID, $type, $data);
                        if($sentEmail == 202) {
                            $response=array("status"=>1,"message"=>"E-mail sent.");
                        } else {
                            $response = array("status"=>0, "message"=>"E-mail not sent!");
                        } 
                    }else{
                        $response = array("status"=>0, "message"=>"Email not found.", "data" => NULL);
                    }
                }
        }
        return $this->respond($response);
    }
    
    public function set_recurring_email(){
        $booking_id  = $this->request->getVar('booking_id');
        $email_id  = $this->request->getVar('email');
        $user_id = $this->request->getVar('user_id');
        
        if(!empty($email_id)){    
            $email = base64_decode($email_id); 
            $check_payment = $this->PaymentInfoModel->getWhere(['booking_id'=>$booking_id,'user_id'=>$user_id])->getRowArray();
            
            if(!empty($check_payment)) {
                $data = array('set_recurring_status' => '1'); 
                $this->AddBookingModel->update($booking_id, $data);
                ?>
                    <script>
                        var userAgent = navigator.userAgent || navigator.vendor || window.opera;
                        function changeLink(applink) 
                        {
                            window.location.href=applink;
                        }
                
                        if( userAgent.match( /iPad/i ) || userAgent.match( /iPhone/i ) || userAgent.match( /iPod/i ) ) 
                        {
                            changeLink("UserMoten://<?php echo base_url(); ?>/recurring?email=<?php echo $email;?>&set_recurring_status=1&booking_id=<?php echo $booking_id; ?>&user_id=<?php echo $user_id; ?>");
                                setInterval(function () {
                                    window.location.replace("https://apps.apple.com/us/app/google/id284815942");
                                }, 3000); 
                        } else if( userAgent.match( /Android/i ) ) {
                            changeLink("UserMoten://<?php echo base_url(); ?>/recurring?email=<?php echo $email;?>&set_recurring_status=1&booking_id=<?php echo $booking_id; ?>&user_id=<?php echo $user_id; ?>");
        
                                setInterval(function () {
                                    window.location.replace("https://play.google.com/store/apps/dev?id=5700313618786177705");
                                }, 3000); 
                        } else {
                            changeLink("UserMoten://<?php echo base_url(); ?>/recurring?email=<?php echo $email;?>&set_recurring_status=1&booking_id=<?php echo $booking_id; ?>&user_id=<?php echo $user_id; ?>");
                            setInterval(function () {
                                window.location.replace("https://www.google.com/");
                            }, 3000); 
                        }
                    </script> 
                <?php
                } else { ?>
                    <script>
                        var userAgent = navigator.userAgent || navigator.vendor || window.opera;
                        function changeLink(applink) 
                        {
                            window.location.href=applink;
                        }
                
                        if( userAgent.match( /iPad/i ) || userAgent.match( /iPhone/i ) || userAgent.match( /iPod/i ) ) 
                        {
                            changeLink("UserMoten://<?php echo base_url(); ?>/recurring?email=<?php echo $email;?>&set_recurring_status=0&booking_id=<?php echo $booking_id; ?>&user_id=<?php echo $user_id; ?>");
                                setInterval(function () {
                                    window.location.replace("https://apps.apple.com/us/app/google/id284815942");
                                }, 3000); 
                        } else if( userAgent.match( /Android/i ) ) {
                            changeLink("UserMoten://<?php echo base_url(); ?>/recurring?email=<?php echo $email;?>&set_recurring_status=0&booking_id=<?php echo $booking_id; ?>&user_id=<?php echo $user_id; ?>");
            
                                setInterval(function () {
                                    window.location.replace("https://play.google.com/store/apps/dev?id=5700313618786177705");
                                }, 3000); 
                        } else {
                            changeLink("UserMoten://<?php echo base_url(); ?>/recurring?email=<?php echo $email;?>&set_recurring_status=0&booking_id=<?php echo $booking_id; ?>&user_id=<?php echo $user_id; ?>");
                            setInterval(function () {
                                window.location.replace("https://www.google.com/");
                            }, 3000); 
                        } 
                    </script> 
                <?php 
                } 
        } else {
            $response = array("status"=>0, "message"=>"Email not found!");
        }
    }
    
    public function editBooking(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $user_id= $userData['id'];
            $booking_id = $this->request->getVar('id');
		    $business_id = $this->request->getVar('business_id');
		    $emp_id = $this->request->getVar('emp_id');
		    $booking_date = $this->request->getVar('booking_date');
		    $booking_timestamp = strtotime($booking_date);
		    $booking_time = $this->request->getVar('booking_time');
		    $time = time(); 
    		$current_date = date("Y-m-d",$time);
    		
    		$current_date = date("Y-m-d");
            
            $get_booking_date = $this->AddBookingModel->getWhere(['id'=>$booking_id])->getRowArray();
            if($get_booking_date['booking_date'] < $current_date){
                $response=array("status"=>0,"message"=>"You cannot edit your bookings on past days!", "data" => NULL); 
            }else{
                if($booking_timestamp >= strtotime($current_date)){
        		    if($emp_id == 0){ //Any staff start
                        $assign_staff = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'status'=>'0'])->getResultArray();
                         if(!empty($assign_staff)){
                             $staffs = $assign_staff;
                         }else{
                             $staffs = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'booking_date >='=>$current_date])->getResultArray();
                         }
                         
                            $staff_id = array();
                            foreach($staffs as $staff){
                                $staff_ids[] = $staff['emp_id'];
                                
                                $get_free_staffs = $this->EmployeeModel->get_free_staffs($staff_ids,$business_id);
                                if(!empty($get_free_staffs)){
                                    foreach($get_free_staffs as $getsid){
                                        $data = [
                                                'user_id'       => $user_id,
                                                'emp_id'        => $getsid['emp_id'],
                                                'booking_date'  => $booking_date,
                                                'booking_time'  => $booking_time,
                                                'business_id'   => $business_id,
                                        ];
                                        break;
                                    }
                                }else{
                                    if($staff['booking_time'] != $booking_time){
                                        $data = [
                                                'user_id'       => $user_id,
                                                'emp_id'        => $staff['emp_id'],
                                                'booking_date'  => $booking_date,
                                                'booking_time'  => $booking_time,
                                                'business_id'   => $business_id,
                                        ]; 
                                   }
                               }
                            }   
                    } //Any staff end
                    else{  
                		$data = [
                		    'user_id'	    => $user_id,
                			'emp_id'	    => $emp_id,
                			'booking_date'	=> $booking_date,
                			'booking_time'	=> $booking_time,
                			'business_id'   => $business_id,
                		];
                    }
    
    		        $result = $this->AddBookingModel->update($booking_id,$data);
    		        $sub_service_id = $this->request->getVar('sub_service_id');
                    $services = explode(',', $sub_service_id);
                    
                    $get_booking_id = $this->AddBookingModel->getWhere(['id' => $booking_id])->getRowArray();
                    if(!empty($get_booking_id)) {
                        $this->BookingsServicesModel->where(['booking_id' => $get_booking_id['id']])->delete();
                        foreach($services as $serve) :
                                $get_sub_nam = $this->SubServiceModel->get_sub_service_name($serve);
                                $data = array(
                                    'sub_service_id' => $serve,
                        			'booking_id'	 => $get_booking_id['id'],
                        			'user_id'        => $user_id,
                        			'sub_service_name' => $get_sub_nam['sub_service_name'],
                                );
                                $result = $this->BookingsServicesModel->save($data);
                        endforeach;
                        $response=array("status"=>1,"message"=>"Booking updated successfully.", "data" => $result);
                    }
                    else {
                        $response=array("status"=>0,"message"=>"Booking not updated, please try again!","data" =>NULL);
                    }
        		}
        		else{
        		    $response=array("status"=>0,"message"=>"Booking date must be greater than or equal to current date!", "data" => NULL);
        		}
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
		return $this->respond($response);
    }
    
    public function viewUpcomingPastBookings(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $user_id= $userData['id'];
            $bookings_type = $this->request->getVar('type'); //1=Upcomings, 0=Past
            
            if($bookings_type == 1 ){ 
                $up_statuses = ['0','3']; //0=Open, 3=Closed
                $get_upcoming_bookings = $this->AddBookingModel->get_upcoming_bookings($user_id,$up_statuses);
                
                if(!empty($get_upcoming_bookings)){
                       foreach($get_upcoming_bookings as $key=>$service) :
                          $business_id = $service['business_id'];
                          $id = $service['business_id'];
                          $type = '0'; 
                          
                          $get_business_img = $this->UserModel->get_business_img($business_id);
                          if(!empty($get_business_img)){
                               $string_version = implode(',', $get_business_img);
                               $get_upcoming_bookings[$key]['business_img'] = $string_version;
                          }else{
                               $get_upcoming_bookings[$key]['business_img'] = "";
                          }
                          
                          $get_business_address = $this->BusinessDetailModel->getWhere(['business_id'=>$business_id])->getRowArray();
                          if(!empty($get_business_address)){
                               $get_upcoming_bookings[$key]['business_details'] = $get_business_address;
                          }else{
                              $default = array (
                                "id" => "",
                                "business_name" => "",
                                "business_address_1" => "",
                                "business_city" => "",
                                "business_province" => "",
                                "business_postal_code" => "",
                                "business_country_code" => "",
                                "business_phone" => "",
                                "business_id" => "",
                                "business_latitude" => "",
                                "business_longitude" => ""
                                );
                                $get_upcoming_bookings[$key]['business_details'] = $default;
                          }
                          
                          if(!empty($business_id)){
                               $get_upcoming_bookings[$key]['distance'] = $this->calculateDistance($user_id,$business_id);
                               $get_upcoming_bookings[$key]['rating'] = $this->calculateRating($id,$type);
                               $get_upcoming_bookings[$key]['reviews'] = $this->calculateReview($id,$type);
                           }
                       endforeach;
                    $response = array("status"=>1, "message"=>"Upcoming Bookings found.", "data" => $get_upcoming_bookings);
                }else{
                    $response = array("status"=>0, "message"=>"No Upcoming Bookings found!", "data" => NULL);
                }
            }
            else{ 
                $past_statuses = ['1','2']; // 2=Cancelled, 1=Completed
                $get_past_bookings = $this->AddBookingModel->get_past_bookings($user_id,$past_statuses);
                if(!empty($get_past_bookings)){
                       foreach($get_past_bookings as $key=>$service) :
                          $business_id = $service['business_id'];
                          
                          $get_business_img = $this->UserModel->get_business_img($business_id);
                          if(!empty($get_business_img)){
                               $string_version = implode(',', $get_business_img);
                               $get_past_bookings[$key]['business_img'] = $string_version;
                          }else{
                               $get_past_bookings[$key]['business_img'] = "";
                          }
                          
                          $get_business_address = $this->BusinessDetailModel->getWhere(['business_id'=>$business_id])->getRowArray();
                          if(!empty($get_business_address)){
                               $get_past_bookings[$key]['business_details'] = $get_business_address;
                          }else{
                              $default = array (
                                "id" => "",
                                "business_name" => "",
                                "business_address_1" => "",
                                "business_city" => "",
                                "business_province" => "",
                                "business_postal_code" => "",
                                "business_country_code" => "",
                                "business_phone" => "",
                                "business_id" => "",
                                "business_latitude" => "",
                                "business_longitude" => ""
                                );
                                $get_past_bookings[$key]['business_details'] = $default;
                          }
                          
                          if(!empty($business_id)){
                               $get_past_bookings[$key]['distance'] = $this->calculateDistance($user_id,$business_id);
                           }
                       endforeach;
                    $response = array("status"=>1, "message"=>"Past Bookings found.", "data" => $get_past_bookings);
                }else{
                    $response = array("status"=>0, "message"=>"You have no previous bookings!", "data" => NULL);
                }
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function bookingDetails(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
                $user_id= $userData['id']; 	
                $booking_id = $this->request->getVar('id'); 
                $booking_discount_amount = $this->request->getVar('discount_amount'); 
            
                $get_completed_booking_details = $this->AddBookingModel->getWhere(['user_id'=>$user_id,'id'=>$booking_id])->getRowArray();
                if(!empty($get_completed_booking_details)){
                          $business_id = $get_completed_booking_details['business_id'];
                          $booking_id = $get_completed_booking_details['id'];
                          $emp_id = $get_completed_booking_details['emp_id'];
                          $user_id = $get_completed_booking_details['user_id'];
                          $booking_id = $get_completed_booking_details['id'];
                          
                          $staff_assigned_img = $this->EmployeeModel->get_emp_img($emp_id);
                          if(!empty($staff_assigned_img)){
                               $string_version = implode(',', $staff_assigned_img);
                               $get_completed_booking_details['staff_img'] = $string_version;
                          }else{
                               $get_completed_booking_details['staff_img'] = "";
                          } 
                          
                          $staff_assigned_first_name = $this->EmployeeModel->get_staff_first_name($emp_id);
                          if(!empty($staff_assigned_first_name)){
                               $string_version = implode(',', $staff_assigned_first_name);
                               $get_completed_booking_details['staff_first_name'] = $string_version;
                          }else{
                               $get_completed_booking_details['staff_first_name'] = "";
                          } 
                          
                          $staff_assigned_last_name = $this->EmployeeModel->get_staff_last_name($emp_id);
                          if(!empty($staff_assigned_last_name)){
                               $string_version = implode(',', $staff_assigned_last_name);
                               $get_completed_booking_details['staff_last_name'] = $string_version;
                          }else{
                               $get_completed_booking_details['staff_last_name'] = "";
                          }
                          
                          $get_business_img = $this->UserModel->get_business_img($business_id);
                          if(!empty($get_business_img)){
                               $string_version = implode(',', $get_business_img);
                               $get_completed_booking_details['business_img'] = $string_version;
                          }else{
                               $get_completed_booking_details['business_img'] = "";
                          }
                         
                          $get_business_address = $this->BusinessDetailModel->getWhere(['business_id'=>$business_id])->getRowArray();
                          if(!empty($get_business_address)){
                               $get_completed_booking_details['business_details'] = $get_business_address;
                          }else{
                                $default = array (
                                "id" => "",
                                "business_name" => "",
                                "business_address_1" => "",
                                "business_address_2" => "",
                                "business_city" => "",
                                "business_province" => "",
                                "business_postal_code" => "",
                                "business_country_code" => "",
                                "business_phone" => "",
                                "business_id" => "",
                                "business_latitude" => "",
                                "business_longitude" => ""
                                );
                                $get_completed_booking_details['business_details'] = $default;
                          }
                           
                          $business_sub_services = $this->BookingsServicesModel->get_open_booking_sub_services($booking_id,$user_id);
                          if(!empty($business_sub_services) && !empty($booking_id)){
                              $get_completed_booking_details['sub_services'] = $business_sub_services; 
                          }else{
                              $get_completed_booking_details['sub_services'] = []; 
                          } 
                          
                          if(!empty($emp_id)){
                              $id = $get_completed_booking_details['emp_id'];
                              $type = '1';
                              $get_completed_booking_details['emp_rating'] = $this->calculateRating($id,$type);
                          }
                          
                          if(!empty($business_id)){
                               $get_booking_rating = $this->RateReviewBusinessEmployeeModel->get_booking_rating_by_user_to_bus($booking_id,$user_id,$business_id);
                               if(!empty($get_booking_rating)){
                                    $get_completed_booking_details['user_rating_to_business'] = $get_booking_rating['rating'];
                                    $get_completed_booking_details['user_review_to_business'] = $get_booking_rating['review'];
                               }else{
                                    $get_completed_booking_details['user_rating_to_business'] = "0";
                                    $get_completed_booking_details['user_review_to_business'] = "0";
                               }
                           }
                           
                           if(!empty($emp_id)){
                               $get_booking_rating = $this->RateReviewBusinessEmployeeModel->get_booking_rating_by_user_to_emp($booking_id,$user_id,$emp_id);
                               if(!empty($get_booking_rating)){
                                    $get_completed_booking_details['user_rating_to_emp'] = $get_booking_rating['rating'];
                                    $get_completed_booking_details['user_review_to_emp'] = $get_booking_rating['review'];
                               }else{
                                    $get_completed_booking_details['user_rating_to_emp'] = "0";
                                    $get_completed_booking_details['user_review_to_emp'] = "0";
                               }
                           }
                           
                           $get_applied_discount_code = $this->AddBookingModel->get_booking_applied_discount_code($user_id,$booking_id);
                           if(!empty($booking_discount_amount)){
                               $string_version = implode(',', $get_applied_discount_code);
                               $get_completed_booking_details['promo_code_applied_percentage'] = $string_version;
                           }else{
                               $get_completed_booking_details['promo_code_applied_percentage'] = "";
                           }
                           
                           $get_booking_payment_details = $this->AddBookingModel->get_booking_payment_details($user_id,$booking_id);
                           if(!empty($get_booking_payment_details)){
                               $get_completed_booking_details['payment_details'] = $get_booking_payment_details;
                           }else{
                               $default = array (
                                    "amount" => "",
                                    "payment_method_type" => "",
                                    "payment_status" => ""
                                );
                                $get_completed_booking_details['payment_details'] = $default;
                           }
                           
                    $response = array("status"=>1, "message"=>"Booking details found.", "data" => $get_completed_booking_details);
                }else{
                    $response = array("status"=>0, "message"=>"Booking details not found!", "data" => NULL);
                }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function cancelBooking(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $user_id= $userData['id'];
            $booking_id = $this->request->getVar('id');
    		$current_date = date("Y-m-d");
            
            $get_booking_date = $this->AddBookingModel->getWhere(['id'=>$booking_id])->getRowArray();
            if($get_booking_date['booking_date'] < $current_date){
                $response=array("status"=>0,"message"=>"You cannot cancel your bookings on past days!", "data" => NULL); 
            }else{
                $data = ['status' => '2']; // 2=Cancelled Booking
                $result = $this->AddBookingModel->update($booking_id, $data);
                if(!empty($result)){
    	             $response=array("status"=>1,"message"=>"Booking cancelled successfully.", "data" => NULL);
    		    }else{
		             $response=array("status"=>0,"message"=>"Booking not cancelled, please try again!", "data" => NULL); 
		        }
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function markAsCompleteBooking(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $user_id= $userData['id'];
            $booking_id = $this->request->getVar('id');
            
            $data = ['status' => "1"]; // 1=Completed Booking
            if(!empty($data)){
                $result = $this->AddBookingModel->update($booking_id, $data);
                if(!empty($result)){
		             $response=array("status"=>1,"message"=>"Booking marked as completed.", "data" => $result);
    		    }else{
    		         $response=array("status"=>0,"message"=>"Booking not marked as completed, please try again!", "data" => NULL); 
    		    }
            }else{
                $response=array("status"=>0,"message"=>"Booking not found!"); 
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    /*public function closeBooking(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $user_id= $userData['id'];
            $booking_id = $this->request->getVar('id');
            
            $data = ['status' => 3]; // 3=Closed Booking
            if(!empty($data)){
                $result = $this->AddBookingModel->update($booking_id, $data);
                if(!empty($result)){
		             $response=array("status"=>1,"message"=>"Booking closed successfully.", "data" => $result);
    		    }else{
    		         $response=array("status"=>0,"message"=>"Booking not closed, please try again!", "data" => NULL); 
    		    }
            }else{
                $response=array("status"=>0,"message"=>"Booking not found!"); 
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }*/
    
    public function favouriteUnfavourite(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $user_id= $userData['id'];
            $type = $this->request->getVar('type'); //2=Business, 3=Employee/Staff
            $favourite_id = $this->request->getVar('favourite_id'); //Whether like Business user or Employee/Staff
            $favourite_status = $this->request->getVar('favourite_status'); //1=Favourite, 0=Unfavourite
            
            if($type == 2){
                 $get_business_name = $this->BusinessDetailModel->getWhere(['business_id' => $favourite_id])->getRowArray();
                 $business_name = $get_business_name['business_name'];
            }else{
                 $get_emp_id = $this->EmployeeModel->getWhere(['emp_id' => $favourite_id])->getRowArray();
                 $business_id = $get_emp_id['business_id'];
                 $business_name_get = $this->EmployeeModel->get_emp_business_name($business_id);
                 $business_name = $business_name_get['business_name'];
            }
            
            if($favourite_status == 1){
        	    $data = [
        			'user_id'	=> $user_id,
        			'type'	=> $type, 
        			'favourite_id'	=> $favourite_id,
        			'favourite_status' => $favourite_status,
        			'business_name'    => $business_name,
        	    ];

        		$checkLikeExist = $this->FavouriteModel->likeExist($user_id,$type,$favourite_id);
        		
        		if($checkLikeExist == 0){
        		    $result = $this->FavouriteModel->insert($data);
        		    if(!empty($result)) {
    		            if($type == 2){
                            $response = array("status"=>1, "message"=>"User Liked successfully.", "data" => $result);
    		            }else{
    		                $response = array("status"=>1, "message"=>"Staff Liked successfully.", "data" => $result);
    		            }
                    }
                    else {
                        if($type == 2){
                                $response = array("status"=>0, "message"=>"User Not liked, please try again!", "data" => NULL);
        		        }else{
        		                $response = array("status"=>0, "message"=>"Staff Not liked, please try again!", "data" => NULL);
        		        }
                    }
        	    }
        	    else{
        	        if($type == 2){
                            $response=array("status"=>0,"message"=>"User already liked, cannot like again!", "data" => NULL);
    		        }else{
    		               $response=array("status"=>0,"message"=>"Staff already liked, cannot like again!", "data" => NULL);
    		        }
        	    }
            }
            else{
                $favouriteID = $this->FavouriteModel->getWhere(['user_id' => $userData['id'], 'type' => $type,'favourite_id' => $favourite_id])->getRowArray();
                
                if(!empty($favouriteID)) {
                    $favid = $favouriteID['id'];
                    $unfavourite = $this->FavouriteModel->where(['id' => $favid])->delete();
                    
                    if($type == 2){
                            $response = array("status"=>1, "message"=>"User disliked successfully.", "data" => NULL);
    		        }else{
    		                $response = array("status"=>1, "message"=>"Staff disliked successfully.", "data" => NULL);
    		        }
                }  
                else {
                    if($type == 2){
                            $response=array("status"=>0,"message"=>"User not exist!", "data" => NULL);
    		        }else{
    		               $response=array("status"=>0,"message"=>"Staff not exist!", "data" => NULL);
    		        }
                } 
            }
        }else{
            $response = array("status"=>0, "message"=>"User not found.", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function favouriteListing(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $user_id = $userData['id'];
            $type = $this->request->getVar('type');
            $favourite_status = '1';
            
            $listing = $this->FavouriteModel->get_like_users_data($type,$favourite_status,$user_id);
            if(!empty($listing)) {
                 if($type == 2){
                     foreach($listing as $key=>$service) :
                       $business_id = $service['favourite_id'];
                       $id = $service['favourite_id'];
                       $type = '0';
                       
                       if(!empty($business_id)){
                           $listing[$key]['distance'] = $this->calculateDistance($user_id,$business_id);
                           $listing[$key]['rating'] = $this->calculateRating($id,$type);
                       }
                       
                     endforeach;
                     
                     $response = array("status"=>1, "message"=>"Liked Businesses Found.", "data" => $listing);
	             }else{
	                 foreach($listing as $key=>$service) :
                       $business_id = $service['favourite_id'];
                       $id = $service['favourite_id'];
                       $type = '1';
                       
                       if(!empty($business_id)){
                           $listing[$key]['rating'] = $this->calculateRating($id,$type);
                       }
                     endforeach;
	                 
	                $response = array("status"=>1, "message"=>"Liked Staffs Found.", "data" => $listing);
	             }
            }  
            else {
                if($type == 2){
                    $response = array("status"=>0, "message"=>"No Favourite Found", "data" => NULL);
	            }else{
	                $response = array("status"=>0, "message"=>"No Favourite Found", "data" => NULL);
	            }
            }
        }else{
           $response = array("status"=>0, "message"=>"User not found.", "data" => NULL); 
        }
        return $this->respond($response);
    }
    
    public function userEmpProfile(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
		if(!empty($userData)){
		    $user_id = $userData['id'];
		    $id = $this->request->getVar('id');
            $type = $this->request->getVar('type'); //0=Business,1=Staff
            
            if($type == "1"){
                $business_img = $this->EmployeeModel->getWhere(["emp_id"=>$id])->getRowArray();
                if(!empty($business_img)){
                           $business_id = $business_img['business_id'];
                           $emp_id = $business_img['emp_id'];
                           $id = $business_img['emp_id'];
                           $type = '1';
                           
                           $business_emp_portfolio = $this->EmployeePortfolioModel->getWhere(["emp_id"=>$emp_id])->getResultArray();
                           if(!empty($business_emp_portfolio) && !empty($emp_id)){
                               $business_img['employee_portfolio'] = $business_emp_portfolio; 
                           }else{
                               $business_img['employee_portfolio'] = []; 
                           }
                           
                           $business_img_back = $this->UserModel->get_business_img($business_id);
                           if(!empty($business_img_back)){
                               $string_version = implode(',', $business_img_back);
                               $business_img['business_img'] = $string_version;
                           }else{
                               $business_img['business_img'] = "";
                           }
                           
                           $favourite_status = $this->FavouriteModel->get_emp_favourite_status($emp_id,$user_id);
                           if(!empty($favourite_status)){
                               $string_version = implode(',', $favourite_status);
                               $business_img['emp_favourite_status'] = $string_version;
                           }else{
                               $business_img['emp_favourite_status'] = "";
                           }
                           
                           $business_img['emp_rating'] = $this->calculateRating($id,$type);
                           
                           $get_emp_reviews = $this->RateReviewBusinessEmployeeModel->get_emp_profile_feedback($emp_id);
                           if(!empty($get_emp_reviews)){
                               foreach($get_emp_reviews as $key => $rated_services_name){
                                   $rated_id = $rated_services_name->id; 
                                   $get_services_name = $this->RatedBookingsServicesModel->get_booking_sub_services($rated_id);
                                   if(!empty($get_services_name)){
                                       $get_emp_reviews[$key]->sub_services= $get_services_name;
                                   }else{
                                       $get_emp_reviews[$key]->sub_services= [];
                                   }
                               }
                               $business_img['reviews'] = $get_emp_reviews;
                           }else{
                               $business_img['reviews'] = [];
                           }
                    $response=array("status"=>1,"message"=>"Employee Profile found.", "data" => $business_img);
                }
                else{
                    $response=array("status"=>0,"message"=>"Employee Profile not found!", "data" =>NULL);
                }  
            }else{
                $business_data = $this->BusinessDetailModel->getWhere(["business_id"=>$id])->getRowArray();
                if(!empty($business_data)){
                    $business_id = $business_data['business_id'];
                    $id = $business_data['business_id'];
                    $type = '0';

                    $business_about = $this->BusinessDetailsWebsiteInfModel->get_business_about($business_id);
                       if(!empty($business_about)){
                           $string_version = implode(',', $business_about);
                           $business_data['what_we_do'] = $string_version;
                       }else{
                           $business_data['what_we_do'] = "";
                       }
                       
                       $business_img_back = $this->UserModel->get_business_img($business_id);
                       if(!empty($business_img_back)){
                           $string_version = implode(',', $business_img_back);
                           $business_data['business_img'] = $string_version;
                       }else{
                           $business_data['business_img'] = "";
                       }
                       
                       if(!empty($business_id)){
                           $business_data['distance'] = $this->calculateDistance($user_id,$business_id);
                           $business_data['rating'] = $this->calculateRating($id,$type);
                           $business_data['reveiws'] = $this->calculateReview($id,$type);
                       }
                       
                       $favourite_status = $this->FavouriteModel->get_business_favourite_status($business_id,$user_id);
                       if(!empty($favourite_status)){
                           $string_version = implode(',', $favourite_status);
                           $business_data['favourite_status'] = $string_version;
                       }else{
                           $business_data['favourite_status'] = "";
                       }
                       
                       $get_business_payment_type = $this->BusinessPaymentTypeModel->get_business_payment_type($business_id);
                       if(!empty($get_business_payment_type)){
                           $convert = implode(',',$get_business_payment_type);
                           $business_data['payment_type'] = $convert;
                       }else{
                           $business_data['payment_type'] = "0";
                       }
                           
                       $response=array("status"=>1,"message"=>"Business found.", "data" => $business_data);
                }else{
                    $response=array("status"=>0,"message"=>"Business not found!", "data" =>NULL);
                }
            }
		}else{
		    $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
		}
		return $this->respond($response);
    }
    
    public function viewSpecialOffers(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
       
        if(!empty($userData)){
              $type = $this->request->getVar('type'); //0=NearBy,1=ValidUntil,2=Discount
              $status = "1";
              
              if($type == "0"){
                  $get_coupons = $this->AddCouponModel->getWhere(['status'=>$status])->getResultArray();
                  if(!empty($get_coupons)){
                      foreach($get_coupons as $key => $coupons){
                          $user_id = $userData['id'];
                          $business_id = $coupons['business_id'];
                          
                          $get_coupons[$key]['distance'] = $this->calculateDistance($user_id,$business_id);
                      }
                      
                      $columns = array_column($get_coupons, 'distance'); //Sort array key in ASC/DESC order
                      array_multisort($columns, SORT_ASC, $get_coupons);
                      
                      $response = array("status"=>1, "message"=>"Special Offers found.", "data" => $get_coupons);
                  }
                  else{
                      $response = array("status"=>0, "message"=>"Special Offers not found!", "data" => NULL);
                  }
              }elseif($type == "1"){
                  $get_validuntilcoupons = $this->AddCouponModel->get_valid_until_coupons($status);
                  if(!empty($get_validuntilcoupons)){
                      $response = array("status"=>1, "message"=>"Special Offers found.", "data" => $get_validuntilcoupons);
                  }
                  else{
                      $response = array("status"=>0, "message"=>"Special Offers not found!", "data" => NULL);
                  }
              }elseif($type == "2"){
                  $get_discountcoupons = $this->AddCouponModel->get_discount_coupons($status);
                  if(!empty($get_discountcoupons)){
                      $response = array("status"=>1, "message"=>"Special Offers found.", "data" => $get_discountcoupons);
                  }
                  else{
                      $response = array("status"=>0, "message"=>"Special Offers not found!", "data" => NULL);
                  }
              }else{
                  $response = array("status"=>0, "message"=>"Special Offers not found!", "data" => NULL);
              }
        }
        else{
            $response=array("status"=>0,"message"=>"User not found!" ,"data" => NULL); 
        }
		return $this->respond($response);
    }
    
    public function viewSpecialOffersDetails(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)){
            $id = $this->request->getVar('id');
            
            $get_special_offers_details = $this->AddCouponModel->getWhere(['id'=>$id])->getRowArray();
            if(!empty($get_special_offers_details)){
                       foreach($get_special_offers_details as $key=>$details) :
                           $coupon_id = $get_special_offers_details['id'];
                           $business_id = $get_special_offers_details['business_id'];
                           
                           $coupon_services = $this->AssignedCouponServicesModel->get_sub_services($coupon_id);
                           if(!empty($coupon_services) && !empty($coupon_id)){
                               $get_special_offers_details['services'] = $coupon_services; 
                           }else{
                               $get_special_offers_details['services'] = []; 
                           }
                           
                           $business_website_about = $this->BusinessDetailsWebsiteInfModel->get_business_about($business_id);
                           if(!empty($business_website_about)){
                               $string_version = implode(',', $business_website_about);
                               $get_special_offers_details['about_this_business'] = $string_version;
                           }else{
                               $get_special_offers_details['about_this_business'] = "";
                           }
                           
                           $business_address = $this->BusinessDetailModel->get_business_address($business_id);
                           if(!empty($business_address)){
                               $get_special_offers_details['business_dtl'] = $business_address;
                           }else{
                               $default = array (
                                    "business_address_1" => "",
                                    "business_address_2" => "",
                                    "business_city" => "",
                                    "business_postal_code" => "",
                                    "business_latitude" => "",
                                    "business_longitude" => "",
                                );
                                $get_special_offers_details['business_dtl'] = $default;



                           }
                        endforeach;
                $response=array("status"=>1,"message"=>"Special Offer Details found.", "data" => $get_special_offers_details);
            }else{
              $response=array("status"=>0,"message"=>"Special Offer Details not found!", "data" =>NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!" ,"data" => NULL); 
        }
        return $this->respond($response);
    }
    
    public function recommendedServices(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $type = $this->request->getVar('type'); //0=NearBy,1=HighestRated,2=MostReviews
            $get_businesses = $this->AdvertisedBusinessModel->get_home_advertised_services_all();
            
            if(!empty($get_businesses)){
                if($type == "0"){
                    foreach($get_businesses as $key => $business){
                          $user_id = $userData['id'];
                          $business_id = $business->business_id;
                          $id = $business->business_id;
                          $type = '0';
                          
                          $get_businesses[$key]->distance = $this->calculateDistance($user_id,$business_id);
                          $get_businesses[$key]->rating= $this->calculateRating($id,$type);
                          $get_businesses[$key]->reviews = $this->calculateReview($id,$type);
                     }
                 
                    $columns = array_column($get_businesses, 'distance');
                    array_multisort($columns, SORT_ASC, $get_businesses);
                }elseif($type == "1"){
                    foreach($get_businesses as $key => $business){
                          $user_id = $userData['id'];
                          $business_id = $business->business_id;
                          $id = $business->business_id;
                          $type = '0';
                          
                          $get_businesses[$key]->distance = $this->calculateDistance($user_id,$business_id);
                          $get_businesses[$key]->rating= $this->calculateRating($id,$type);
                          $get_businesses[$key]->reviews = $this->calculateReview($id,$type);
                     }
                     
                    $columns = array_column($get_businesses, 'rating'); 
                    array_multisort($columns, SORT_DESC, $get_businesses);
                }else{
                    foreach($get_businesses as $key => $business){
                          $user_id = $userData['id'];
                          $business_id = $business->business_id;
                          $id = $business->business_id;
                          $type = '0';
                          
                          $get_businesses[$key]->distance = $this->calculateDistance($user_id,$business_id);
                          $get_businesses[$key]->rating= $this->calculateRating($id,$type);
                          $get_businesses[$key]->reviews = $this->calculateReview($id,$type);
                     }
                     
                    $columns = array_column($get_businesses, 'reviews'); 
                    array_multisort($columns, SORT_DESC, $get_businesses);
                }
                
                $response = array("status"=>1, "message"=>"Recommended Services found.", "data" => $get_businesses);
            }else{
                $response = array("status"=>0, "message"=>"Recommended Services not found!", "data" => NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!" ,"data" => NULL); 
        }
        return $this->respond($response);
    }
    
    public function availableToday(){ //is_open =>0=Open,1=Closed
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $user_id = $userData['id']; 
            $type = $this->request->getVar('type'); //0=NearBy,1=HighestRated,2=MostReviews
            
                $get_today_avaiable_services = $this->UserModel->get_user_business_img_status();
                if(!empty($get_today_avaiable_services)){
                        if($type == "0"){
                            foreach($get_today_avaiable_services as $key => $business){
                              $business_id = $business['business_id'];
                              $id = $business['business_id'];
                              $type = '0';
                          
                              $get_today_avaiable_services[$key]['distance'] = $this->calculateDistance($user_id,$business_id);
                              $get_today_avaiable_services[$key]['rating'] = $this->calculateRating($id,$type);
                              $get_today_avaiable_services[$key]['reviews'] = $this->calculateReview($id,$type);
                            }
                        
                            $columns = array_column($get_today_avaiable_services, 'distance');
                            array_multisort($columns, SORT_ASC, $get_today_avaiable_services);
                        }elseif($type == "1"){
                            foreach($get_today_avaiable_services as $key => $business){
                              $business_id = $business['business_id'];
                              $id = $business['business_id'];
                              $type = '0';
                          
                              $get_today_avaiable_services[$key]['distance'] = $this->calculateDistance($user_id,$business_id);
                              $get_today_avaiable_services[$key]['rating'] = $this->calculateRating($id,$type);
                              $get_today_avaiable_services[$key]['reviews'] = $this->calculateReview($id,$type);
                            }
                        
                            $columns = array_column($get_today_avaiable_services, 'rating'); 
                            array_multisort($columns, SORT_DESC, $get_today_avaiable_services);
                        }else{
                            foreach($get_today_avaiable_services as $key => $business){
                              $business_id = $business['business_id'];
                              $id = $business['business_id'];
                              $type = '0';
                          
                              $get_today_avaiable_services[$key]['distance'] = $this->calculateDistance($user_id,$business_id);
                              $get_today_avaiable_services[$key]['rating'] = $this->calculateRating($id,$type);
                              $get_today_avaiable_services[$key]['reviews'] = $this->calculateReview($id,$type);
                            }
                        
                            $columns = array_column($get_today_avaiable_services, 'reviews'); 
                            array_multisort($columns, SORT_DESC, $get_today_avaiable_services);
                        }
                       
                        $response = array("status"=>1, "message"=>"Today Available Services found.", "data" => $get_today_avaiable_services);
                }
                else{
                    $response = array("status"=>1, "message"=>"No Services available today!", "data" => NULL);
                }
        }else{
            $response=array("status"=>0,"message"=>"User not found!" ,"data" => NULL); 
        }
        return $this->respond($response);
    }
    
    public function addserviceCategory(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)){
            if($userData['user_type'] == 2) {
                $service_name	= $this->request->getVar('service_name');
    		    $business_industry	= $this->request->getVar('business_industry');
    		    $business_id = $userData['id'];
                $countService = $this->ServiceCategoryModel->checkserviceExist($service_name,$business_industry,$business_id);
                if($countService > 0) {
                    $response=array("status"=>0,"message"=>"Service category already added!" ,"data" => NULL); 
                } else {
                    $data = [
                        'service_name'	=> $service_name,
                        'business_industry'	=> $business_industry,
                        'business_id' => $business_id,
                    ];
                    
                    if(!empty($data)){
                        $add_service_category = $this->ServiceCategoryModel->insert($data);
                        
                        $get_added_service_id['service_id'] = $last_inserted_id = $this->ServiceCategoryModel->insertID();
                        $response=array("status"=>1,"message"=>"Service category added successfully.", "data " => $get_added_service_id);
                    }else{
                       $response=array("status"=>0,"message"=>"Service category not added, please try again!" ,"data" => NULL); 
                    }
                } 
            }else{
                $response = array("status"=>0, "message"=>"You are not a business User.", "data" => NULL); 
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!" ,"data" => NULL); 
        }
		return $this->respond($response);
    }

    public function editserviceCategory(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $service_name	= $this->request->getVar('service_name');
    		$service_id	= $this->request->getVar('service_id');
            
            $data = [
                'service_name'	=> $service_name,
            ];
            
            if(!empty($data)){
                $result = $this->ServiceCategoryModel->update($service_id, $data);
                $serviceData = $this->ServiceCategoryModel->getWhere(["service_id" => $service_id])->getRowArray();
                $response=array("status"=>1,"message"=>"Service category updated successfully.", "data " => $serviceData);
            }else{
                $response=array("status"=>0,"message"=>"Service category not updated, please try again!" ,"data" => NULL); 
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!" ,"data" => NULL);
        }
		
		return $this->respond($response);
    }

    public function delserviceCategory(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
		
		if(!empty($userData)){
		     $business_id = $userData['id'];
		     $service_id	= $this->request->getVar('service_id');
		    
             $serviceData = $this->ServiceCategoryModel->getWhere(["service_id" => $service_id])->getRowArray();
            
            if(!empty($serviceData)){
                $subserviceData = $this->SubServiceModel->getWhere(["service_id" => $service_id])->getRowArray();
                
                if(!empty($subserviceData)) {
                   
                    $delete = $this->SubServiceModel->where(['service_id' =>$service_id , 'business_id' => $business_id])->delete();
                    $delete1 = $this->ServiceCategoryModel->where(['service_id' =>$service_id , 'business_id' => $business_id])->delete();
                }  
                else {
                    $delete = $this->ServiceCategoryModel->where(['service_id' =>$service_id , 'business_id'=> $business_id])->delete();
                } 
                $response=array("status"=>1,"message"=>"Service category deleted successfully.");
            }
            else{
                $response=array("status"=>0,"message"=>"Service category not found!" ,"data" => NULL); 
            }
		}
		else{
		    $response=array("status"=>0,"message"=>"User not found!" ,"data" => NULL); 
		}
		
		return $this->respond($response);
    }
    
    public function editsubService(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $id = $this->request->getVar('id');
            $sub_service_name = $this->request->getVar('sub_service_name');
            $sub_service_price = $this->request->getVar('sub_service_price');
            $sub_service_duration = $this->request->getVar('sub_service_duration');
            $sub_service_desc = $this->request->getVar('sub_service_desc');
            $service_id = $this->request->getVar('service_id');
            $business_id = $userData['id'];
            
    		$data = [
    			'sub_service_name'		=> $sub_service_name,
    			'sub_service_price'		=>  $sub_service_price,
    			'sub_service_duration'	=> $sub_service_duration,
    			'sub_service_desc'		=> $sub_service_desc,
    			'service_id'			=>  $service_id,
    			'business_id'			=>  $business_id,
    		];
    		
    		if(!empty($data)){
    		    $result = $this->SubServiceModel->update($id, $data);
    		    $response=array("status"=>1,"message"=>"Sub Service updated successfully.", "data " => $result);
    		}else{
    		    $response=array("status"=>0,"message"=>"Sub Service not updated, please try again!", "data " => NULL);
    		}
        }else{
            $response=array("status"=>0,"message"=>"User not found!" ,"data" => NULL); 
        }
		return $this->respond($response);
    }
    
    public function deletesubService(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $id = $this->request->getVar('id');
    	    $delete = $this->SubServiceModel->where('id', $id)->delete();
    	    if(!empty($delete)){
    	        $response=array("status"=>1,"message"=>"Sub Service deleted successfully.", "data " => $delete);
    	    }else{
    	        $response=array("status"=>0,"message"=>"Sub Service not found.");
    	    }
        }else{
            $response=array("status"=>0,"message"=>"User not found!" ,"data" => NULL); 
        }
		return $this->respond($response);   
    }
    
    public function addemployeeService() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $empID = $this->request->getVar('emp_id');
                $serviceIDs = $this->request->getVar('service_id');
                $subserviceIDs = $this->request->getVar('sub_service_id');
                
                $employeeServiceData = explode(",",$serviceIDs);
                $employeesubServiceData = explode(",",$subserviceIDs);
                
                $employeeserveData = $this->EmployeeServiceModel->getWhere(['emp_id' => $empID])->getResultArray();
                
                if(!empty($employeeserveData)) {
                    $this->EmployeeServiceModel->where(['emp_id' => $empID])->delete();
                }
                
                $employeesubserveData = $this->EmployeeSubServiceModel->getWhere(['emp_id' =>$empID])->getResultArray();
                
                if(!empty($employeesubserveData)) {
                    $this->EmployeeSubServiceModel->where(['emp_id' => $empID])->delete();
                }
                
                foreach($employeeServiceData as $serve) :
                    $serviceData = array('emp_id' => $empID, 'service_id' => $serve);
                    $this->EmployeeServiceModel->save($serviceData);
                endforeach;
                
                foreach($employeesubServiceData as $subserve) :
                      $subserviceData = array('emp_id' => $empID, 'sub_service_id' => $subserve);
                    $this->EmployeeSubServiceModel->save($subserviceData);
                endforeach;
                
                $employeeData = array('is_completed' => '2');
                $this->EmployeeModel->update($empID, $employeeData);
                
                $updatedemployeeData = $this->EmployeeModel->getWhere(['emp_id' => $empID])->getRowArray();

                $response=array("status"=>1,"message"=>"Service added successfully.", "data " => $updatedemployeeData);  
            } else {
                $response = array("status"=>0, "message"=>"You are not a business User.", "data" => NULL); 
            }       
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);    
    }
    
    public function addemployeePortfolio() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $empID = $this->request->getVar('emp_id');
                $filesEmployee = $this->request->getFileMultiple('img');
                $files = $_FILES['img']['name'];
                 
                if($files[0] != "") {
                    foreach($this->request->getFileMultiple('img') as $key => $fileEmployee) {
                            $picArr = [
                                'emp_id' => $empID,
                                'emp_img' => $fileEmployee->getRandomName()
                            ];
                            
                                $fileEmployee->move('public/employeePort', $picArr['emp_img']);
                                $result2 = $this->EmployeePortfolioModel->save($picArr);
                    }
                    
                 $employeeData = array('is_completed' => '3');      
                 $this->EmployeeModel->update($empID, $employeeData);
                
                 $updatedemployeeData = $this->EmployeeModel->getWhere(['emp_id' => $empID])->getRowArray();
                 
                 $imagesemployeeData = $this->EmployeePortfolioModel->get_emp_portfolio($empID);
                 
                 $response=array("status"=>1,"message"=>"Employee portfolio added successfully.", "data " => $updatedemployeeData, "images" => $imagesemployeeData);  
                }else{
                    $response=array("status"=>0,"message"=>"Employee portfolio not added, please try again!", "data " => NULL); 
                }
            } else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }       
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);    
    }  
    
    public function getemployeeHours() {
        $userId = $this->decodeToken();
        
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $empID = $this->request->getVar('emp_id');
                $workData = $this->EmployeeWorkingHourModel->get_employee_working_hours($empID);
                $columns = array_column($workData, 'id');
                array_multisort($columns, SORT_ASC, $workData);
                if(!empty($workData)) {
                    foreach($workData as $key => $breaks) {
                        $week_id = $breaks->id;
                        
                        //For breaks
                        $listBreaks = $this->EmployeeBreakModel->getWhere(["week_id" => $week_id, "emp_id" => $empID])->getResultArray();
                        if(!empty($listBreaks)){
                            $workData[$key]->break_time=$listBreaks;
                        }else{
                            $workData[$key]->break_time=[];
                        }

                        if(!empty($listBreaks)){
                            $workData[$key]->default_break="false"; //Breaks added
                        }else{
                            $workData[$key]->default_break="true"; //Breaks not added
                        }
                        
                        //For working hours
                        $listHours = $this->AddEmpWorkingHoursModel->getWhere(["week_id" => $week_id, "emp_id" => $empID])->getResultArray();
                        if(!empty($listHours)){
                            $workData[$key]->working_hours=$listHours;
                        }else{
                            $workData[$key]->working_hours=[];
                        }

                        if(!empty($listHours)){
                            $workData[$key]->default_working_hours="false"; //Working Hours added
                        }else{
                            $workData[$key]->default_working_hours="true"; //Working Hours not added
                        }
                    }
                    $response = array("status"=>1, "message"=>"Working Hours found.", "data" => $workData);
                } else {
                     $response = array("status"=>0, "message"=>"Working Hours not found", "data" => NULL);
                }
            } else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }     
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);     
    }
    
    public function updateemployeeHours() {
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $empID = $this->request->getVar('emp_id');
                $userWeekDay = $this->request->getVar('weekdayId');
                $userOpenTime = $this->request->getVar('openingtime');
                $userCloseTime = $this->request->getVar('closingtime');
                $userFromBreak = $this->request->getVar('frombreak');
                $userToBreak = $this->request->getVar('tobreak');
                $userWorkStatus = $this->request->getVar('workstatus');
                
                $weekData = $this->EmployeeWorkingHourModel->getWhere(["id" => $userWeekDay, "emp_id" => $empID])->getRowArray(); 
                
                if(!empty($weekData)) {
                    $data = array('opening_time' => $userOpenTime, 'closing_time' => $userCloseTime, 'from_break_time' => $userFromBreak, 'to_break_time' => $userToBreak, 'work_status' => $userWorkStatus);
                    $result = $this->EmployeeWorkingHourModel->update($userWeekDay, $data);
                    $updatedworkingHours = $this->EmployeeWorkingHourModel->getWhere(["id" => $userWeekDay])->getRowArray();
                    
                    $employeeData = array('is_completed' => '4');      
                    $this->EmployeeModel->update($empID, $employeeData);
                    
                    $updatedemployeeData = $this->EmployeeModel->getWhere(['emp_id' => $empID])->getRowArray();
                    
                    $response = array("status"=>1, "message"=>"Changes saved successfully!", "data" => $updatedworkingHours, "employeedata" => $updatedemployeeData);
                }  else {
                    $response = array("status"=>0, "message"=>"Working Hours not found", "data" => []);
                }
            } else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }     
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response);     
    }
    
    public function addEmployeeBreak(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
             if($userData['user_type'] == 2) {
                $empID = $this->request->getVar('emp_id');
                $week_id = $this->request->getVar('week_id');
                $start_break_time = $this->request->getVar('start_break_time');
                $end_break_time = $this->request->getVar('end_break_time');
                
                $weekData = $this->EmployeeWorkingHourModel->getWhere(["emp_id" => $empID, "id" => $week_id])->getRowArray(); 
                if(!empty($weekData)) {
                        $data = [     
                                      'emp_id' => $weekData['emp_id'], 
                                      'week_id' => $weekData['id'], 
                                      'start_break_time' => $start_break_time, 
                                      'end_break_time' =>$end_break_time
                                ];
                        $this->EmployeeBreakModel->insert($data);
                        $response = array("status"=>1, "message"=>"Employee Break added successfully!", "data" => $data);
                } else {
                        $response = array("status"=>0, "message"=>"Employee Break not added, please try again!", "data" => []);
                }
             } 
             else {
                $response = array("status"=>0, "message"=>"You are not a Business User.", "data" => NULL); 
             } 
        }
        else{
                $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response);     
    }
    
    public function deleteEmployeeBreak(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
                $empID = $this->request->getVar('emp_id');
                $id = $this->request->getVar('id');
                
                if(!empty($id)) {
                        $this->EmployeeBreakModel->where(['emp_id' => $empID, 'id' => $id])->delete();
                        $response = array("status"=>1, "message"=>"Employee Break deleted successfully!");
                } else {
                    $response = array("status"=>0, "message"=>"Employee Break not deleted, please try again!", "data" => []);
                }
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function getBusinessAddedEmployee(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
             $business_id = $userData['id'];
             $business_emps = $this->EmployeeModel->get_business_employees_list($business_id);
             if(!empty($business_emps)){
                 $response = array("status"=>1, "message"=>"Employees found!", "data" => $business_emps);
             }else{
                 $response = array("status"=>0, "message"=>"No Employees found!", "data" => NULL);
             }
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function editBusinessEmployee(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
		
        if(!empty($userData)) {
            $emp_id = $this->request->getVar('emp_id');
            $emp_img = $this->request->getFile('emp_img');
            $emp_first_name = $this->request->getVar('emp_first_name');
            $emp_last_name = $this->request->getVar('emp_last_name');
            $emp_desc = $this->request->getVar('emp_desc');
            $userEmail = $this->request->getVar('emp_email');
            $emp_gender = $this->request->getVar('emp_gender');
            $emp_title = $this->request->getVar('emp_title');
            $emp_country_code = $this->request->getVar('emp_country_code');
            $emp_phone_number = $this->request->getVar('emp_phone_number');

                if( ($emp_img != '') && (isset($emp_img)) ) {
                        $ext = $emp_img->getClientExtension();
                            
                        if( ($ext == "png") || ($ext == "jpg") || ($ext == "gif") || ($ext == "jpeg") ) {
                            $name = $emp_img->getRandomName();
                            
                            $get_emp_image = $this->EmployeeModel->getWhere(['emp_id' =>$emp_id])->getRowArray();
                            $filename = $get_emp_image['emp_img'];
                            if($filename) {
                                unlink(FCPATH . 'public/employeeImg/'.$filename);
                            } 
                            
                            $emp_img->move('public/employeeImg', $name);
                            $data = [
                    			'emp_img'		 => $name,
                    			'emp_first_name' =>  $emp_first_name,
                    			'emp_last_name'	 => $emp_last_name,
                    			'emp_desc'		 => $emp_desc,
                    			'emp_email'		 => $userEmail,
                    			'emp_gender'	 => $emp_gender,
                    			'emp_title'	     => $emp_title,
                    			'country_code'	=> $emp_country_code,
                    			'phone_number'	=> $emp_phone_number,
                    		];
                        } else {
                            $data = array();
                            $response=array("status"=>0,"message"=>"Please upload jpg|png|jpeg|gif image format.");
                        }      
                } 
                else {
                     $data = [
            			'emp_first_name' => $emp_first_name,
            			'emp_last_name'	 => $emp_last_name,
            			'emp_desc'		 => $emp_desc,
            			'emp_email'		 => $userEmail,
            			'emp_gender'	 => $emp_gender,
            			'emp_title'	     => $emp_title,
            			'country_code'	=> $emp_country_code,
                    	'phone_number'	=> $emp_phone_number,
            		];
                }    
    		    
    		    if(!empty($data)){
    		            $get_data = $this->EmployeeModel->getWhere(['emp_id'=>$emp_id])->getRowArray();
    		            if($get_data['phone_number'] == $emp_phone_number){
    		                $result = $this->EmployeeModel->update($emp_id, $data);
    		                $response = array("status"=>1, "message"=>"Details updated successfully.", "data" => $result);
    		            }else{
    		                $check_phone_existence = $this->EmployeeModel->checkEmpphoneExist($emp_phone_number);
                            if($check_phone_existence == 0){
                                $result = $this->EmployeeModel->update($emp_id, $data);
                                $response = array("status"=>1, "message"=>"Details updated successfully.", "data" => $result);
                            }else{
                                $response = array("status"=>0, "message"=>"Mobile no. already exists!", "data" => NULL);
                            } 
    		            }
    		    }else{
    		        $response = array("status"=>0, "message"=>"Details not updated, please try again!", "data" => NULL);
    		    }
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function deleteBusinessEmployee(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            $emp_id = $this->request->getVar('emp_id');
            if(!empty($emp_id)){
                $deleteemp = $this->EmployeeModel->where(['emp_id' =>$emp_id , 'business_id' => $userData['id']])->delete();
                $response = array("status"=>1, "message"=>"Employee deleted successfully.");
            }else{
                $response = array("status"=>0, "message"=>"Employee not deleted, please try again!", "data" => NULL);
            }
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function markBusinessEmployeeTitle(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            $emp_id = $this->request->getVar('emp_id');
            $emp_title = $this->request->getVar('emp_title');
            $is_mark_as_manager = $this->request->getVar('mark_as_manager');
            
            $data = [
                'emp_title' => $emp_title,
                'is_mark_as_manager' => $is_mark_as_manager,
            ];
            
            if(!empty($data)){
                $emp_title= $this->EmployeeModel->update($emp_id, $data);
                $response = array("status"=>1, "message"=>"Employee marked as Manager successfully.");
            }else{
                $response = array("status"=>0, "message"=>"Employee not marked as Manager, please try again!", "data" => NULL);
            }
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function unmarkBusinessEmployeeTitle(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            $emp_id = $this->request->getVar('emp_id');
            $emp_title = 'Employee';
            $is_mark_as_manager = '0';
            
            $data = [
                'emp_title' => $emp_title,
                'is_mark_as_manager' => $is_mark_as_manager,
            ];
            
            if(!empty($emp_id)){
                $emp_title= $this->EmployeeModel->update($emp_id, $data);
                $response = array("status"=>1, "message"=>"Employee unmarked successfully.");
            }else{
                $response = array("status"=>0, "message"=>"Employee not unmarked, please try again!", "data" => NULL);
            }
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function deactivateBusinessEmployee(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            $emp_id = $this->request->getVar('emp_id');
            $emp_active_status = $this->request->getVar('emp_active_status'); //0=Active, 1=Inactive
            
            $data = [
    			'emp_active_status'	=> $emp_active_status,
    		];
    		
            if(!empty($data)){
                $emp_title= $this->EmployeeModel->update($emp_id, $data);
                $response = array("status"=>1, "message"=>"Employee deactivated successfully.");
            }else{
                $response = array("status"=>0, "message"=>"Employee not deactivated, please try again!", "data" => NULL);
            }
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function viewBusinessEmployeeDetails(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            $emp_id = $this->request->getVar('emp_id');
            $empData = $this->EmployeeModel->get_emp($emp_id);
            $business_id=$userData['id'];
            
            if(!empty($empData)) {
                    $businessImgData = $this->UserModel->get_business_img($business_id);
                    if(!empty($businessImgData['user_img'])){
                        $empData['background_img'] =$businessImgData;
                    }else{
                        $empData['background_img'] ="";
                    }
                    
                    $empID = $empData['emp_id'];
                    $emplistPortfolio = $this->EmployeePortfolioModel->getWhere(["emp_id" => $empID])->getResultArray();
                    if(!empty($emplistPortfolio)){
                        $empData['portfolio'] =$emplistPortfolio;
                    }else{
                        $empData['portfolio'] =[];
                    }
                   
                    $employeeSubServices = $this->EmployeeSubServiceModel->empSubServices($empID);
                    if(!empty($employeeSubServices)){
                        $empData['sub_services'] =$employeeSubServices;
                    }else{
                        $empData['sub_services'] =[];
                    }
                    
                    $id = $empData['emp_id'];
                    $type = "1";
                    $empData['emp_rating'] = $this->calculateRating($id,$type);

                    $get_emp_reviews = $this->RateReviewBusinessEmployeeModel->get_emp_profile_feedback($emp_id);
                    if(!empty($get_emp_reviews)){
                       foreach($get_emp_reviews as $key => $rated_services_name){
                           $rated_id = $rated_services_name->id; 
                           $get_services_name = $this->RatedBookingsServicesModel->get_booking_sub_services($rated_id);
                           if(!empty($get_services_name)){
                               $get_emp_reviews[$key]->sub_services = $get_services_name;
                           }else{
                               $get_emp_reviews[$key]->sub_services= [];
                           }
                       }
                       $empData['reviews'] = $get_emp_reviews;
                    }else{
                       $empData['reviews'] = [];
                    }
                $response = array("status"=>1, "message"=>"Employee details found.", "data" => $empData);
            } 
            else {
                 $response = array("status"=>0, "message"=>"Employee details not found!", "data" => NULL);
            }
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function deleteEmpPortfolio(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            $emp_id = $this->request->getVar('emp_id');
            $file= $this->request->getVar('portfolio_img');
            
            if( ($file != '') && (isset($file)) ) {
                unlink( FCPATH . "public/employeePort/" . $file );
                $query = $this->EmployeePortfolioModel->where(['emp_id' =>$emp_id , 'emp_img' => $file])->delete();
                $rest_images = $this->EmployeePortfolioModel->getWhere(["emp_id" => $emp_id])->getResultArray();
                $response = array("status"=>1, "message"=>"Portfolio Deleted successfully.", "data" => $rest_images);
            } 
            else{
                $response = array("status"=>0, "message"=>"Portfolio not deleted, please try again!", "data" => NULL);
            }
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }

    public function editBusinessOwnerDetails(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $first_name = $this->request->getVar('first_name');
                $last_name = $this->request->getVar('last_name');
                $email = $this->request->getVar('email');
                $country_code = $this->request->getVar('country_code');
                $userPhn = $this->request->getVar('mobile');
                
                    $data = [
                                'first_name' => $first_name,
                                'last_name'  => $last_name,
                                'email' => $email,
                                'country_code' => $country_code,
                                'mobile' => $userPhn,
                            ];
                            
                    if(!empty($data)) {
                        //if($userData['mobile'] == $userPhn){
                            $edit_data = $this->UserModel->update($userData['id'], $data);
                            $updateduserData = $this->UserModel->get_single_userdata($userData['id']);
                            $userToken = $this->encodeToken($updateduserData);
                            $response = array("status"=>1, "message"=>"Owner's details are successfully updated.", "data" => $updateduserData,"token" => $userToken);
                        /*}else{
                            $check_phone_existence = $this->UserModel->checkmobileExist($userPhn);
                            if($check_phone_existence == 0){
                                $edit_data = $this->UserModel->update($userData['id'], $data);
                                $updateduserData = $this->UserModel->get_single_userdata($userData['id']);
                                $userToken = $this->encodeToken($updateduserData);
                                $response = array("status"=>1, "message"=>"Owner's details are successfully updated.", "data" => $updateduserData,"token" => $userToken);
                            }else{
                                $response = array("status"=>0, "message"=>"Mobile no. already exists!", "data" => NULL);
                            }
                        }*/
                    }  
                    else {
                        $response = array("status"=>0, "message"=>"Owner's details not updated, please try again!", "data" => []);
                    }
            } 
            else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }     
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response); 
    }
    
    public function getBusinessDetails(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $business_details = $this->BusinessDetailModel->getWhere(["business_id" => $userData['id']])->getRowArray();
                if(!empty($business_details)) {
                    $response = array("status"=>1, "message"=>"Business Details found.", "data" => $business_details);
                }  else {
                    $response = array("status"=>0, "message"=>"Business Details not found!", "data" => []);
                }
            } 
            else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }     
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response); 
    }
    
    public function addBusinessImage(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $business_img = $this->request->getFile('business_img');
                if( ($business_img != '') && (isset($business_img)) ) {
                    $ext = $business_img->getClientExtension();
                        
                    if( ($ext == "png") || ($ext == "jpg") || ($ext == "gif") || ($ext == "jpeg") ) {
                        $name = $business_img->getRandomName();
                        
                        $business_img->move('public/userImg', $name);
                        $data = array('user_img' => $name);
                     } 
                     else {
                        $data = array();
                        $response=array("status"=>0,"message"=>"Please upload jpg|png|jpeg|gif image format.");
                    }      
                } 
                else{
                }
                $add_business_img = $this->UserModel->update($userData['id'], $data);
                if(!empty($add_business_img)){
                    $response = array("status"=>1, "message"=>"Image uploaded successfully.", "data" => NULL); 
                }else{
                    $response = array("status"=>0, "message"=>"Image not uploaded, please try again!", "data" => NULL); 
                }
            } 
            else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }     
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response); 
    }
    
    public function editBusinessDetails(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $business_dtl_id = $this->request->getVar('business_dtl_id');
                $business_name = $this->request->getVar('business_name');
                $business_address_1 = $this->request->getVar('business_address_1');
                $business_address_2 = $this->request->getVar('business_address_2');
                $business_city = $this->request->getVar('business_city');
                $business_province = $this->request->getVar('business_province');
                $business_postal_code = $this->request->getVar('business_postal_code');
                $business_country_code = $this->request->getVar('business_country_code');
                $business_phone = $this->request->getVar('business_phone');
                $userlatitude = $this->request->getVar('latitude');
                $userlongitude = $this->request->getVar('longitude');
                
                $data = [
                    'business_name' => $business_name,
                    'business_address_1' => $business_address_1,
                    'business_address_2' => $business_address_2,
                    'business_city' => $business_city,
                    'business_province' => $business_province,
                    'business_postal_code' => $business_postal_code,
                    'business_country_code' => $business_country_code,
                    'business_phone' => $business_phone,
                    'business_latitude' => $userlatitude,
                    'business_longitude' => $userlongitude,
                ];
                if(!empty($data)){
                    $get_business_mobile = $this->BusinessDetailModel->getWhere(['business_id'=>$userData['id'],'id'=>$business_dtl_id])->getRowArray();
                    if($get_business_mobile['business_phone'] == $business_phone){
                        $this->BusinessDetailModel->update($business_dtl_id, $data);
                        $updated_data = $this->BusinessDetailModel->getWhere(["business_id" => $userId])->getRowArray();
                        $response = array("status"=>1, "message"=>"Details updated successfully.", "data" => $updated_data); 
                    }else{
                        $check_phone_existence = $this->BusinessDetailModel->checkBusinessMobileExist($business_phone);
                        if($check_phone_existence == 0){
                            $this->BusinessDetailModel->update($business_dtl_id, $data);
                            $updated_data = $this->BusinessDetailModel->getWhere(["business_id" => $userId])->getRowArray();
                            $response = array("status"=>1, "message"=>"Details updated successfully.", "data" => $updated_data); 
                        }else{
                            $response = array("status"=>0, "message"=>"Mobile no. already exists!", "data" => NULL);
                        }
                    }
                }else{
                    $response = array("status"=>0, "message"=>"Details not found!", "data" => NULL); 
                }
            } 
            else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }     
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response); 
    }
    
    public function addBusinessHealthAndSafetyPolicy(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $get_health_and_safety = $this->BusinessDetailAdditionalInformationModel->getWhere(['slug'=>'health-and-safety','business_id' => $userData['id']])->getRowArray();
                $id = $get_health_and_safety['id'];
                $slug = "health-and-safety";
                $health_and_safety_policy = $this->request->getVar('health_and_safety_policy');
                
                if(!empty($get_health_and_safety)){
                    $data = [
                        'content' => $health_and_safety_policy,
                        'status'  => "1"
                    ];
                    
                        $edit_business_web_Details = $this->BusinessDetailAdditionalInformationModel->update($id, $data);
                        
                        $updated_data = $this->BusinessDetailAdditionalInformationModel->getWhere(['slug'=>'health-and-safety','business_id' => $userData['id']])->getRowArray();
                        if(!empty($edit_business_web_Details)){
                            $response = array("status"=>1, "message"=>"Health & Safety Policy updated successfully.", "data" => $updated_data); 
                        }else{
                            $response = array("status"=>0, "message"=>"Health & Safety Policy not updated!", "data" => NULL); 
                        }
                }else{
                    $data = [
                        'slug' => $slug,
                        'content' => $health_and_safety_policy,
                        'business_id' => $userData['id'],
                    ];
                    if(!empty($data)) {
                        $insert_policy = $this->BusinessDetailAdditionalInformationModel->insert($data);
                        $response = array("status"=>1, "message"=>"Health & Safety Policy updated successfully.", "data" => $insert_policy);
                    } else {
                        $response = array("status"=>0, "message"=>"Health and Safety Policy not updated!", "data" => NULL);
                    } 
                }
            }else{
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response);  
    }
    
    public function addBusinessCancellationPolicy(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $get_cancellation_policy = $this->BusinessDetailAdditionalInformationModel->getWhere(['slug'=>'cancellation-policy','business_id' => $userData['id']])->getRowArray();
                $id = $get_cancellation_policy['id'];
                $slug = "cancellation-policy";
                $canellation_policy = $this->request->getVar('cancellation_policy');
                
                if(!empty($get_cancellation_policy)){
                     $data = [
                        'content' => $canellation_policy,
                        'status'  => "1"
                     ];
                        $edit_business_web_Details = $this->BusinessDetailAdditionalInformationModel->update($id, $data);
                        
                        $updated_data = $this->BusinessDetailAdditionalInformationModel->getWhere(['slug'=>$slug,'business_id' => $userData['id']])->getRowArray();
                        if(!empty($edit_business_web_Details)){
                            $response = array("status"=>1, "message"=>"Cancellation Policy updated successfully.", "data" => $updated_data); 
                        }else{
                            $response = array("status"=>0, "message"=>"Cancellation Policy not updated!", "data" => NULL); 
                        }
                }else{
                    $data = [
                        'slug' => $slug,
                        'content' => $canellation_policy,
                        'business_id' => $userData['id'],
                    ];
                    
                    if(!empty($data)) {
                        $insert_policy = $this->BusinessDetailAdditionalInformationModel->insert($data);
                        $response = array("status"=>1, "message"=>"Cancellation Policy updated successfully.", "data" => $insert_policy);
                    } else {
                        $response = array("status"=>0, "message"=>"Cancellation Policy not updated!", "data" => NULL);
                    } 
                }
            }else{
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response);  
    }
    
    public function addBusinessAmenities(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                
                $get_amenities = $this->BusinessDetailAdditionalInformationModel->getWhere(['slug'=>'amenities','business_id' => $userData['id']])->getRowArray();
                $id = $get_amenities['id'];
                $slug = "amenities";
                $amenities = $this->request->getVar('amenities');
                
                if(!empty($get_amenities)){ 
                    //Edit
                    
                    $data = [
                        'content' => $amenities,
                        'status'  => "1"
                    ];
                    
                    $edit_business_web_Details = $this->BusinessDetailAdditionalInformationModel->update($id, $data);
                    
                    $updated_data = $this->BusinessDetailAdditionalInformationModel->getWhere(['slug'=>'amenities','business_id' => $userData['id']])->getRowArray();
                    if(!empty($edit_business_web_Details)){
                        $response = array("status"=>1, "message"=>"Amenities updated successfully.", "data" => $updated_data); 
                    }else{
                        $response = array("status"=>0, "message"=>"Amenities not updated!", "data" => NULL); 
                    }
                }else{ 
                    //Add
                    
                    $data = [
                        'slug' => $slug,
                        'content' => $amenities,
                        'business_id' => $userData['id'],
                    ];
                    
                    if(!empty($data)) {
                        $insert_amenities = $this->BusinessDetailAdditionalInformationModel->insert($data);
                        $response = array("status"=>1, "message"=>"Amenities updated successfully.", "data" => $insert_amenities);
                    } else {
                        $response = array("status"=>0, "message"=>"Amenities not updated!", "data" => NULL);
                    } 
               }
            }else{
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response);  
    }
    
    public function addBusinessWebsiteInfo(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $about_us = $this->request->getVar('about_us');
                $website = $this->request->getVar('website');
                $email = $this->request->getVar('email');
                
                $data = [
                    'about_us' => $about_us,
                    'website' => $website,
                    'email' => $email,
                    'business_id' => $userData['id'],
                ];
                if(!empty($data)) {
                    $website_info = $this->BusinessDetailsWebsiteInfModel->insert($data);
                    $response = array("status"=>1, "message"=>"About Us, Website & Email saved successfully.", "data" => $website_info);
                } else {
                    $response = array("status"=>0, "message"=>"About Us, Website & Email not saved, please try again!", "data" => NULL);
                } 
            }else{
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response);  
    }
    
    public function getBusinessWebsiteDetails(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $get_bus_website_data = $this->BusinessDetailsWebsiteInfModel->getWhere(['business_id' => $userData['id']])->getRowArray();
                if(!empty($get_bus_website_data)) {
                    $response = array("status"=>1, "message"=>"Details found.", "data" => $get_bus_website_data);
                } else {
                    $response = array("status"=>0, "message"=>"Details not found, please try again!", "data" => NULL);
                } 
            }else{
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response);  
    }
    
    public function editBusinessWebsiteDetails(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $business_website_id = $this->request->getVar('business_website_id');
                $about_us = $this->request->getVar('about_us');
                $website = $this->request->getVar('website');
                $email = $this->request->getVar('email');
                
                $data = [
                    'about_us' => $about_us,
                    'website' => $website,
                    'email' => $email,
                ];
                
                if(!empty($data)){
                    $edit_business_web_Details = $this->BusinessDetailsWebsiteInfModel->update($business_website_id, $data);
                    
                    $updated_data = $this->BusinessDetailsWebsiteInfModel->getWhere(['business_id' => $userData['id']])->getRowArray();
                    if(!empty($edit_business_web_Details)){
                        $response = array("status"=>1, "message"=>"Details updated successfully.", "data" => $updated_data); 
                    }else{
                        $response = array("status"=>0, "message"=>"Details not updated, please try again!", "data" => NULL); 
                    }
                }else{
                    $response = array("status"=>0, "message"=>"Details not found!", "data" => NULL); 
                }
            }else{
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response);  
    }
    
    public function getBusinessAmenities(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $get_bus_website_data = $this->BusinessDetailAdditionalInformationModel->getWhere(['slug'=>'amenities','business_id' => $userData['id']])->getRowArray();
                if(!empty($get_bus_website_data)) {
                    $response = array("status"=>1, "message"=>"Amenities found.", "data" => $get_bus_website_data);
                } else {
                    $response = array("status"=>0, "message"=>"Amenities not found, please try again!", "data" => NULL);
                } 
            }else{
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response);  
    }
    
    public function getBusinessCancellationPolicy(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $get_bus_website_data = $this->BusinessDetailAdditionalInformationModel->getWhere(['slug'=>'cancellation-policy','business_id' => $userData['id']])->getRowArray();
                if(!empty($get_bus_website_data)) {
                    $response = array("status"=>1, "message"=>"Cancellation Policy found.", "data" => $get_bus_website_data);
                } else {
                    $response = array("status"=>0, "message"=>"Cancellation Policy not found, please try again!", "data" => NULL);
                } 
            }else{
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response);  
    }
    
    public function getBusinessHealthSafety(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $get_bus_website_data = $this->BusinessDetailAdditionalInformationModel->getWhere(['slug'=>'health-and-safety','business_id' => $userData['id']])->getRowArray();
                if(!empty($get_bus_website_data)) {
                    $response = array("status"=>1, "message"=>"Health & Safety Policy found.", "data" => $get_bus_website_data);
                } else {
                    $response = array("status"=>0, "message"=>"Health & Safety Policy not found, please try again!", "data" => NULL);
                } 
            }else{
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response);  
    }
    
    public function addBusinessPortfolio(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $business_id = $userData['id'];
                $filesBusiness = $this->request->getFileMultiple('img');
                $files = $_FILES['img']['name'];
                 
                if($files[0] != "") {
                    foreach($this->request->getFileMultiple('img') as $key => $fileBusiness) {
                            $picArr = [
                                'business_id' => $userData['id'],
                                'business_img' => $fileBusiness->getRandomName()
                            ];
                            
                            $fileBusiness->move('public/userPort', $picArr['business_img']);
                            $result = $this->BusinessPortfolioModel->save($picArr);
                    }
                    $businessUserData = $this->UserModel->getWhere(['id' => $userData['id']])->getRowArray();
                    
                    $imagesbusData = $this->BusinessPortfolioModel->get_business_portfolio($business_id);
                    $response=array("status"=>1,"message"=>"Portfolio added successfully.", "data " => $businessUserData, "portfolio" => $imagesbusData);  
                }else{
                    $response=array("status"=>0,"message"=>"Portfolio not added, please try again!", "data " => NULL);
                }
            } 
            else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }       
        }  
        else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
        return $this->respond($response);    
    }
    
    public function deleteBusinessPortfolio(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            $file= $this->request->getVar('business_img');
            
            if( ($file != '') && (isset($file)) ) {
                unlink( FCPATH . "public/userPort/" . $file );
                $query = $this->BusinessPortfolioModel->where(['business_id' =>$userData['id'] , 'business_img' => $file])->delete();
                $rest_images = $this->BusinessPortfolioModel->getWhere(['business_id' =>$userData['id']])->getResultArray();
                $response = array("status"=>1, "message"=>"Portfolio Deleted successfully.", "data" => $rest_images);
            } 
            else{
                $response = array("status"=>0, "message"=>"Portfolio not deleted, please try again!", "data" => NULL);
            }
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function deactivateBusinessAccount(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $is_active = $this->request->getVar('is_active'); //0=Active, 1=Inactive
                
                $data = [
        			'is_active'	=> $is_active,
        		];
        		
                if(!empty($data)){
                    $deactivateAccount = $this->UserModel->update($userData['id'], $data);
                    $this->logout();
                    $response = array("status"=>1, "message"=>"Account deactivated successfully.");
                }else{
                    $response = array("status"=>0, "message"=>"Account not deactivated, please try again!", "data" => NULL);
                }
            } 
            else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
        }
        return $this->respond($response); 
    }
    
   public function addCoupon(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $id = $this->request->getVar('id');
                $discount_code = $this->request->getVar('discount_code');
                $discount = $this->request->getVar('discount');
                $banner_img = $this->request->getFile('banner_img');
                $tagline = $this->request->getVar('tagline');
                $description = $this->request->getVar('description');
                $fine_print = $this->request->getVar('fine_print');
                $start_date = $this->request->getVar('start_date');
                $expiration_date = $this->request->getVar('expiration_date');
                $status = $this->request->getVar('status');
                $business_id = $userData['id'];
                $business_name = $this->BusinessDetailModel->get_business_industry_name($business_id);
                $bus_name = $business_name['business_name']; 
                
                if( ($banner_img != '') && (isset($banner_img)) ) {
                    $ext = $banner_img->getClientExtension();
                    if( ($ext == "png") || ($ext == "jpg") || ($ext == "gif") || ($ext == "jpeg") ) {
                        $name = $banner_img->getRandomName();
                        
                        $banner_img->move('public/couponImg', $name);
                        $data = array('discount_code'=>$discount_code,'discount'=>$discount,'business_name' =>$bus_name, 'banner_img' => $name,'tagline' => $tagline,'description' => $description,'fine_print' => $fine_print,'start_date' => $start_date,'expiration_date' => $expiration_date,'business_id' => $business_id,'status' =>$status);
                     } 
                     else {
                        $data = array();
                        $response=array("status"=>0,"message"=>"Please upload jpg|png|jpeg|gif image format.");
                    }      
                } 
                else{
                    $data = array('discount_code'=>$discount_code,'discount'=>$discount,'business_name' =>$bus_name, 'tagline' => $tagline,'description' => $description,'fine_print' => $fine_print,'start_date' => $start_date,'expiration_date' => $expiration_date,'business_id' => $business_id,'status' =>$status);
                }
        		
        		$add_coupon = $this->AddCouponModel->insert($data);
        		$last_inserted_id = $this->AddCouponModel->insertID();
        		
        		$coupon_services = $this->request->getVar('sub_service_id');
        		$services = explode(',', $coupon_services);
                if(!empty($services)) {
                    foreach($services as $serve) :
                        $data = array(
                            'coupon_id' => $last_inserted_id,
                            'sub_service_id' => $serve
                        );
                
                        $result = $this->AssignedCouponServicesModel->save($data);
                    endforeach;
                    $response=array("status"=>1,"message"=>"Coupon added successfully.", "data" => $result);
                }else{
                    $response=array("status"=>0,"message"=>"Coupon not added, please add again!");
                }
            } 
            else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
        }
        return $this->respond($response); 
   }
   
    public function getCoupons(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $coupons = $this->AddCouponModel->get_coupons($userId);
                
                foreach($coupons as $key => $sub_services) {
                    $coupon_id = $sub_services->id; 
                    
                    $busSubServices = $this->AssignedCouponServicesModel->get_sub_services($coupon_id);
                    if(!empty($busSubServices)){
                        $coupons[$key]->sub_services=$busSubServices;
                    }else{
                        $coupons[$key]->sub_services=[];
                    }
                }
                if(!empty($coupons)){
                    $response=array("status"=>1,"message"=>"Coupons found.", "data" => $coupons);
                }else{
                    $response=array("status"=>0,"message"=>"Coupons not found!", "data" =>NULL);
                }
            } 
            else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
        }
        return $this->respond($response); 
    }
   
   public function getCouponDetails(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $id = $this->request->getVar('id'); 
                
                $get_coupon_details = $this->AddCouponModel->getWhere(['id'=>$id,'business_id'=>$userData['id']])->getRowArray();
                if(!empty($get_coupon_details)){
                            $coupon_id = $get_coupon_details['id'];
                           
                            $coupon_sub_services = $this->AssignedCouponServicesModel->get_sub_services($coupon_id);
                            if(!empty($coupon_sub_services)){
                                $get_coupon_details['sub_services'] = $coupon_sub_services;
                            }else{
                                $get_coupon_details['sub_services'] = "";
                            }
                    $response = array("status"=>1, "message"=>"Coupon details found.", "data" => $get_coupon_details);
                }else{
                    $response = array("status"=>0, "message"=>"Coupon details not found!", "data" => NULL);
                }
            } 
            else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
        }
        return $this->respond($response); 
   }
    
   public function editCoupon(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $id = $this->request->getVar('id');
                $file = $this->request->getFile('banner_img');
                $discount_code = $this->request->getVar('discount_code');
                $tagline = $this->request->getVar('tagline');
                $description = $this->request->getVar('description');
                $fine_print = $this->request->getVar('fine_print');
                $start_date = $this->request->getVar('start_date');
                $expiration_date = $this->request->getVar('expiration_date');
                $status = $this->request->getVar('status');
                $discount = $this->request->getVar('discount');
                
                if( ($file != '') && (isset($file)) ) {
                    $ext = $file->getClientExtension();
                    if( ($ext == "png") || ($ext == "jpg") || ($ext == "gif") || ($ext == "jpeg") ) {
                        $name = $file->getRandomName();
    
                        $get_banner_image = $this->AddCouponModel->getWhere(['business_id' =>$userData['id'],'id' => $id])->getRowArray();
                        $filename = $get_banner_image['banner_img'];
                        if($filename) {
                            unlink(FCPATH . 'public/couponImg/'.$filename);
                        } 
                        
                        $file->move('public/couponImg/', $name);
                        $data =['discount_code'=>$discount_code,'discount'=>$discount,'banner_img' =>$name ,'tagline' => $tagline,'description' => $description,'fine_print' => $fine_print,'start_date' => $start_date,'expiration_date' => $expiration_date,'business_id' => $userData['id'],'status' =>$status];
                    } 
                    else {
                        $response=array("status"=>0,"message"=>"Please upload jpg|png|jpeg|gif image format.");
                    } 
                }
                else{
                    $data = array('discount_code'=>$discount_code,'discount'=>$discount,'tagline' => $tagline,'description' => $description,'fine_print' => $fine_print,'start_date' => $start_date,'expiration_date' => $expiration_date,'business_id' => $userData['id'],'status' =>$status);
                }
                
                $edit_coupon = $this->AddCouponModel->update($id, $data);
                
                $coupon_services = $this->request->getVar('sub_service_id');
        		$services = explode(',', $coupon_services);
        		$get_coupon_id = $this->AddCouponModel->getWhere(['id' => $id])->getRowArray();
        		
                if(!empty($get_coupon_id)) {
                    $this->AssignedCouponServicesModel->where(['coupon_id' => $get_coupon_id['id']])->delete();
                    foreach($services as $serve) :
                            $data = array(
                                'coupon_id' => $get_coupon_id['id'],
                                'sub_service_id' => $serve
                            );
                            $result = $this->AssignedCouponServicesModel->save($data);
                    endforeach;
                    $response=array("status"=>1,"message"=>"Coupon details updated successfully.", "data" => $result);
                }else {
                    $response=array("status"=>0,"message"=>"Coupon details not updated, please try again!");
                }
            } 
            else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
       }
       else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
       }
    return $this->respond($response); 
   }
   
   public function deleteCoupon(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);
       
       if(!empty($userData)) {
             if($userData['user_type'] == 2) {
                    $id = $this->request->getVar('id');
                
                    if(!empty($id)) {
                        $this->AddCouponModel->where(['business_id' => $userData['id'], 'id' => $id])->delete();
                        $this->AssignedCouponServicesModel->where(['coupon_id' => $id])->delete();
                        $response = array("status"=>1, "message"=>"Coupon deleted successfully!");
                    } else {
                        $response = array("status"=>0, "message"=>"Coupon not deleted, please try again!", "data" => []);
                    }
             } 
             else {
                $response = array("status"=>0, "message"=>"You are not a Business User.", "data" => NULL); 
             } 
        }
        else{
                $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response);   
   }
  
   public function addBusinessBreak(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
             if($userData['user_type'] == 2) {
                $week_id = $this->request->getVar('week_id');
                $start_break_time = $this->request->getVar('start_break_time');
                $end_break_time = $this->request->getVar('end_break_time');
                
                $weekData = $this->BusinessWorkingHourModel->getWhere(["business_id" => $userData['id'], "id" => $week_id])->getRowArray(); 
                if(!empty($weekData)) {
                        $data = [     
                                      'business_id' =>  $userData['id'], 
                                      'week_id' => $weekData['id'], 
                                      'start_break_time' => $start_break_time, 
                                      'end_break_time' =>$end_break_time
                                ];
                        $this->BusinessBreakModel->insert($data);
                        $response = array("status"=>1, "message"=>"Business Break added successfully!", "data" => $data);
                } else {
                        $response = array("status"=>0, "message"=>"Business Break not added, please try again!", "data" => []);
                }
             } 
             else {
                $response = array("status"=>0, "message"=>"You are not a Business User.", "data" => NULL); 
             } 
        }
        else{
                $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response);     
    }
   
   public function deleteBusinessBreak(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
                $id = $this->request->getVar('id');
                
                if(!empty($id)) {
                        $this->BusinessBreakModel->where(['business_id' => $userData['id'], 'id' => $id])->delete();
                        $response = array("status"=>1, "message"=>"Business Break deleted successfully!");
                } else {
                    $response = array("status"=>0, "message"=>"Business Break not deleted, please try again!", "data" => []);
                }
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function addBusinessWorkingHours(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
             if($userData['user_type'] == 2) {
                $week_id = $this->request->getVar('week_id');
                $opening_time = $this->request->getVar('opening_time');
                $closing_time = $this->request->getVar('closing_time');
                
                $weekData = $this->BusinessWorkingHourModel->getWhere(["business_id" => $userData['id'], "id" => $week_id])->getRowArray(); 
                if(!empty($weekData)) {
                        $data = [     
                                      'business_id' =>  $userData['id'], 
                                      'week_id' => $weekData['id'], 
                                      'opening_time' => $opening_time, 
                                      'closing_time' =>$closing_time,
                                ];
                        $this->AddBusinessWorkingHoursModel->insert($data);
                        $response = array("status"=>1, "message"=>"Business Working Hours added successfully!", "data" => $data);
                } else {
                        $response = array("status"=>0, "message"=>"Business Working Hours not added, please try again!", "data" => []);
                }
             } 
             else {
                $response = array("status"=>0, "message"=>"You are not a Business User.", "data" => NULL); 
             } 
        }
        else{
                $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response);     
    }
    
    public function addEmpWorkingHours(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
             if($userData['user_type'] == 2) {
                $week_id = $this->request->getVar('week_id');
                $emp_id = $this->request->getVar('emp_id');
                $opening_time = $this->request->getVar('opening_time');
                $closing_time = $this->request->getVar('closing_time');
                
                $weekData = $this->EmployeeWorkingHourModel->getWhere(["emp_id" => $emp_id, "id" => $week_id])->getRowArray(); 
                if(!empty($weekData)) {
                        $data = [     
                                      'emp_id' =>  $weekData['emp_id'], 
                                      'week_id' => $weekData['id'], 
                                      'opening_time' => $opening_time, 
                                      'closing_time' =>$closing_time,
                                ];
                        $this->AddEmpWorkingHoursModel->insert($data);
                        $response = array("status"=>1, "message"=>"Employee Working Hours added successfully!", "data" => $data);
                } else {
                        $response = array("status"=>0, "message"=>"Employee Working Hours not added, please try again!", "data" => []);
                }
             } 
             else {
                $response = array("status"=>0, "message"=>"You are not a Business User.", "data" => NULL); 
             } 
        }
        else{
                $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response);     
    }
    
    public function deleteBusinessWorkingHours(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
                $id = $this->request->getVar('id');
                
                if(!empty($id)) {
                        $this->AddBusinessWorkingHoursModel->where(['business_id' => $userData['id'], 'id' => $id])->delete();
                        $response = array("status"=>1, "message"=>"Business Working hour deleted successfully!");
                } else {
                    $response = array("status"=>0, "message"=>"Business Working hour not deleted, please try again!", "data" => []);
                }
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function deleteEmpWorkingHours(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
                $id = $this->request->getVar('id');
                $emp_id = $this->request->getVar('emp_id');
                
                if(!empty($id)) {
                        $this->AddEmpWorkingHoursModel->where(['emp_id' => $emp_id, 'id' => $id])->delete();
                        $response = array("status"=>1, "message"=>"Employee Working hour deleted successfully!");
                } else {
                    $response = array("status"=>0, "message"=>"Employee Working hour not deleted, please try again!", "data" => []);
                }
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function empViewDetails(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
         
        if(!empty($userData)) {
                  $empData = $this->EmployeeModel->get_single_userdata($userId);
                  
                  if(!empty($empData)){
                          $id = $empData['emp_id'];
                          $type = "1";
                          $business_id = $empData['business_id'];
                          
                          $businessImgData = $this->UserModel->get_business_img($business_id);
                          if(!empty($businessImgData['user_img'])){ 
                                $convert = implode(',', $businessImgData);
                                $empData['background_img'] = $convert;
                          }
                          else{
                                $empData['background_img'] = "";
                          }
                          
                          $bus_dtl = $this->UserModel->get_business_dtl($business_id);
                          if(!empty($bus_dtl)){
                                $empData['business_details'] =$bus_dtl;
                          }
                          else{
                                $default = array (
                                    "id" => "",
                                    "business_name" => "",
                                    "business_address_1" => "",
                                    "business_city" => "",
                                    "business_province" => "",
                                    "business_postal_code" => "",
                                    "business_country_code" => "",
                                    "business_phone" => "",
                                    "business_id" => "",
                                    "business_latitude" => "",
                                    "business_longitude" => ""
                                );
                                $empData['business_details'] = $default;
                          }
                          
                          $empID = $empData['emp_id'];
                          $emplistPortfolio = $this->EmployeePortfolioModel->get_emp_portfolio($empID);
                          if(!empty($emplistPortfolio)){
                                $empData['emp_portfolio'] =$emplistPortfolio;
                          }else{
                                $empData['emp_portfolio'] =[];
                          }
                          
                          $employeeSubServices = $this->EmployeeSubServiceModel->empSubServices($empID);
                          if(!empty($employeeSubServices)){
                            $empData['sub_services'] =$employeeSubServices;
                          }
                          else{
                            $empData['sub_services'] =[];
                          }
                          
                          $empData['emp_rating'] = $this->calculateRating($id,$type);

                            $get_emp_reviews = $this->RateReviewBusinessEmployeeModel->get_emp_profile_feedback($empID);
                            if(!empty($get_emp_reviews)){
                               foreach($get_emp_reviews as $key => $rated_services_name){
                                   $rated_id = $rated_services_name->id; 
                                   $get_services_name = $this->RatedBookingsServicesModel->get_booking_sub_services($rated_id);
                                   if(!empty($get_services_name)){
                                       $get_emp_reviews[$key]->sub_services = $get_services_name;
                                   }else{
                                       $get_emp_reviews[$key]->sub_services= [];
                                   }
                               }
                               $empData['reviews'] = $get_emp_reviews;
                            }else{
                               $empData['reviews'] = [];
                            }
                      $response = array("status"=>1, "message"=>"Details found.", "data" => $empData);
                  }else{
                      $response = array("status"=>0, "message"=>"Details not found!", "data" => NULL);
                  }
        } 
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function editEmpDetails(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
         
        if(!empty($userData)) {
            $file = $this->request->getFile('emp_img');
            $emp_first_name = $this->request->getVar('emp_first_name');
            $emp_last_name = $this->request->getVar('emp_last_name');
            $emp_email = $this->request->getVar('emp_email');
            $emp_title = $this->request->getVar('emp_title');
            $emp_desc = $this->request->getVar('emp_desc');
            $emp_gender = $this->request->getVar('emp_gender');
            
            if( ($file != '') && (isset($file)) ) {
                    $ext = $file->getClientExtension();
                        
                    if( ($ext == "png") || ($ext == "jpg") || ($ext == "gif") || ($ext == "jpeg") ) {
                        $name = $file->getRandomName();
                        
                        $get_emp_image = $this->EmployeeModel->getWhere(['emp_id' =>$userData['emp_id']])->getRowArray();
                        $filename = $get_emp_image['emp_img'];
                        if($filename) {
                            unlink(FCPATH . 'public/employeeImg/'.$filename);
                        } 
                        
                        $file->move('public/employeeImg', $name);
                        $data = [
                			'emp_img'		 => $name,
                			'emp_first_name' => $emp_first_name,
                			'emp_last_name'	 => $emp_last_name,
                			'emp_desc'		 => $emp_desc,
                			'emp_email'		 => $emp_email,
                			'emp_title'	     => $emp_title,
                			'emp_gender'	 => $emp_gender,
                		];
                    } else {
                        $data = array();
                        $response=array("status"=>0,"message"=>"Please upload jpg|png|jpeg|gif image format.");
                    }      
            } 
            else {
                 $data = [
        			'emp_first_name' => $emp_first_name,
        			'emp_last_name'	 => $emp_last_name,
        			'emp_desc'		 => $emp_desc,
        			'emp_email'		 => $emp_email,
        			'emp_title'	     => $emp_title,
        			'emp_gender'	 => $emp_gender,
        		];
            }   
            
            if(!empty($data)){
		        $this->EmployeeModel->update($userData['emp_id'], $data);
		        $result = $this->EmployeeModel->getWhere(['emp_id'=>$userData['emp_id']])->getRowArray();
		        $response = array("status"=>1, "message"=>"Details updated successfully.", "data" => $result);
		    }else{
		        $response = array("status"=>0, "message"=>"Details not updated, please try again!", "data" => NULL);
		    }
		    
        } 
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function getBusinessPortfolio(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
           $business_id = $userData['id'];
            if($userData['user_type'] == 2) {
                  $buslistPortfolio = $this->BusinessPortfolioModel->get_business_portfolio($business_id);
                  if(!empty($buslistPortfolio)){
                     $response=array("status"=>1,"message"=>"Portfolio found.", "data" => $buslistPortfolio);
                  }
                  else{
                     $response=array("status"=>0,"message"=>"Business's Portfolio not found!", "data" =>NULL);
                  }
            } 
            else {
                $response = array("status"=>0, "message"=>"You are not a business User", "data" => NULL); 
            }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
        }
        return $this->respond($response); 
    }
    
    public function getEmployeePortfolio(){ //Business
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
                  $empID = $this->request->getVar('emp_id');
                  
                  $emplistPortfolio = $this->EmployeePortfolioModel->get_emp_portfolio($empID);
                  if(!empty($emplistPortfolio)){
                     $response=array("status"=>1,"message"=>"Portfolio found.", "data" => $emplistPortfolio);
                  }
                  else{
                     $response=array("status"=>0,"message"=>"Portfolio not found!", "data" =>NULL);
                  }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
        }
        return $this->respond($response); 
    }
    
    public function getEmpPort(){ //Employee
       $userId = $this->empdecodeToken();
       $userData = $this->EmployeeModel->get_single_userdata($userId);

       if(!empty($userData)) {
                  $empID = $userData['emp_id'];
                  
                  $emplistPortfolio = $this->EmployeePortfolioModel->get_emp_portfolio($empID);
                  if(!empty($emplistPortfolio)){
                     $response=array("status"=>1,"message"=>"Portfolio found.", "data" => $emplistPortfolio);
                  }
                  else{
                     $response=array("status"=>0,"message"=>"Portfolio not found!", "data" =>NULL);
                  }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
        }
        return $this->respond($response); 
    }
    
    public function addEmpPort(){
       $userId = $this->empdecodeToken();
       $userData = $this->EmployeeModel->get_single_userdata($userId);

       if(!empty($userData)) {
            $filesBusiness = $this->request->getFileMultiple('img');
            $files = $_FILES['img']['name'];
             
            if($files[0] != "") {
                foreach($this->request->getFileMultiple('img') as $key => $fileBusiness) {
                        $picArr = [
                            'emp_id' => $userData['emp_id'],
                            'emp_img' => $fileBusiness->getRandomName()
                        ];
                        
                            $fileBusiness->move('public/employeePort', $picArr['emp_img']);
                            $result = $this->EmployeePortfolioModel->save($picArr);
                }
            }
            
            $imagesempData = $this->EmployeePortfolioModel->getWhere(['emp_id' =>  $userData['emp_id']])->getResultArray();
            
            $response=array("status"=>1,"message"=>"Portfolio added successfully.", "portfolio" => $imagesempData);       
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
        }
        return $this->respond($response); 
    }
    
    public function deleteEmployeePortfolio(){
       $userId = $this->empdecodeToken();
       $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            $file= $this->request->getVar('emp_portfolio_img');
            
            if( ($file != '') && (isset($file)) ) {
                unlink( FCPATH . "public/employeePort/" . $file );
                $query = $this->EmployeePortfolioModel->where(['emp_id' =>  $userData['emp_id'] , 'emp_img' => $file])->delete();
                
                $rest_images = $this->EmployeePortfolioModel->getWhere(['emp_id' =>  $userData['emp_id']])->getResultArray();
                $response = array("status"=>1, "message"=>"Portfolio Deleted successfully.", "data" => $rest_images);
            } 
            else{
                $response = array("status"=>0, "message"=>"Portfolio not deleted, please try again!", "data" => NULL);
            }
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function empAddServices(){
       $userId = $this->empdecodeToken();
       $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            $serviceIDs = $this->request->getVar('service_id');
            $subserviceIDs = $this->request->getVar('sub_service_id');
            
            $employeeServiceData = explode(",",$serviceIDs);
            $employeesubServiceData = explode(",",$subserviceIDs);
            
            $employeeserveData = $this->EmployeeServiceModel->getWhere(['emp_id' => $userData['emp_id']])->getResultArray();
            if(!empty($employeeserveData)) {
                $this->EmployeeServiceModel->where(['emp_id' => $userData['emp_id']])->delete();
            }
            
            $employeesubserveData = $this->EmployeeSubServiceModel->getWhere(['emp_id' =>$userData['emp_id']])->getResultArray();
            if(!empty($employeesubserveData)) {
                $this->EmployeeSubServiceModel->where(['emp_id' => $userData['emp_id']])->delete();
            }
            
            foreach($employeeServiceData as $serve) :
                $serviceData = array('emp_id' => $userData['emp_id'], 'service_id' => $serve);
                $this->EmployeeServiceModel->save($serviceData);
            endforeach;
            
            foreach($employeesubServiceData as $subserve) :
                  $subserviceData = array('emp_id' => $userData['emp_id'], 'sub_service_id' => $subserve);
                $this->EmployeeSubServiceModel->save($subserviceData);
            endforeach;
            
            $response=array("status"=>1,"message"=>"Services updated successfully."); 
        }
        else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
     public function empViewServices(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
              $emp_id = $userData['emp_id'];
              
              $get_services = $this->EmployeeServiceModel->empServices($emp_id);
                if(!empty($get_services)){
                    foreach($get_services as $key => $services){
                        $service_id = $services['service_id'];
                        
                        $business_sub_services = $this->SubServiceModel->getWhere(["service_id" => $service_id])->getResultArray();
                        $emp_sub_services = array();
                        foreach($business_sub_services as $sub_services){
                            $sub_service_id = $sub_services['id'];
                            
                            $emp_services = $this->EmployeeSubServiceModel->emp_service_sub_service($emp_id,$sub_service_id);
                            if ( !empty ($emp_services) ) {
                                $emp_sub_services[] = $emp_services;
                                if(!empty($emp_sub_services)){
                                    $get_services[$key]['sub_services'] = $emp_sub_services;
                                }else{
                                    $get_services[$key]['sub_services'] = [];
                                }
                            }
                        }
                    }
                    $response=array("status"=>1,"message"=>"Services found.", "data" => $get_services);
                }else{
                    $response=array("status"=>0,"message"=>"Services not found.", "data" => NULL);
                }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    public function searchServices(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)){
            $user_id = $userData['id'];
            $user_lat = $userData['latitude'];
            $user_long = $userData['longitude'];
            
            $business_name = $this->request->getVar('business_name');
            $on_date = $this->request->getVar('date');
            $min_distance = $this->request->getVar('min_distance');
            $max_distance = $this->request->getVar('max_distance');
            $lat = $this->request->getVar('lat');
            $long = $this->request->getVar('long');
            $type = $this->request->getVar('type'); //0=NearBy,1=HighestRated,2=MostReviews
            
            if(empty($business_name)){
                $get_calgary_businesses = $this->BusinessDetailModel->get_calgary_businesses();
                if($type == "0"){
                    foreach($get_calgary_businesses as $key => $calgary_businesses){
                        $business_id = $calgary_businesses->business_id;
                        $id =  $calgary_businesses->business_id;
                        $type = '0';
                        
                        $get_calgary_businesses[$key]->rating = $this->calculateRating($id,$type);
                        $get_calgary_businesses[$key]->reviews = $this->calculateReview($id,$type);
                        $get_calgary_businesses[$key]->distance = $this->calculateDistance($user_id,$business_id);
                    }
                    
                    $columns = array_column($get_calgary_businesses, 'distance'); 
                    array_multisort($columns, SORT_ASC, $get_calgary_businesses);
                }elseif($type == "1"){
                    foreach($get_calgary_businesses as $key => $calgary_businesses){
                        $business_id = $calgary_businesses->business_id;
                        $id =  $calgary_businesses->business_id;
                        $type = '0';
                        
                        $get_calgary_businesses[$key]->rating = $this->calculateRating($id,$type);
                        $get_calgary_businesses[$key]->reviews = $this->calculateReview($id,$type);
                        $get_calgary_businesses[$key]->distance = $this->calculateDistance($user_id,$business_id);
                    }
                    
                    $columns = array_column($get_calgary_businesses, 'rating'); 
                    array_multisort($columns, SORT_DESC, $get_calgary_businesses);
                }else{
                    foreach($get_calgary_businesses as $key => $calgary_businesses){
                        $business_id = $calgary_businesses->business_id;
                        $id =  $calgary_businesses->business_id;
                        $type = '0';
                        
                        $get_calgary_businesses[$key]->rating = $this->calculateRating($id,$type);
                        $get_calgary_businesses[$key]->reviews = $this->calculateReview($id,$type);
                        $get_calgary_businesses[$key]->distance = $this->calculateDistance($user_id,$business_id);
                    }
                    
                    $columns = array_column($get_calgary_businesses, 'reviews'); 
                    array_multisort($columns, SORT_DESC, $get_calgary_businesses);
                }
                $response = array("status"=>1, "message"=>"Services found.", "data" => $get_calgary_businesses);
            }else{
                $services = $this->BusinessDetailModel->get_search_services($business_name,$user_lat,$user_long,$min_distance,$max_distance,$lat,$long);
                if(!empty($services)){
                    
                    if(!empty($on_date)){
                        $filter_services = array();
                        
                        if($type == "0"){
                            foreach($services as $key => $service) :
                                $business_id = $service->business_id;
                                $id =  $service->business_id;
                                $type = '0';
                               
                                $services[$key]->rating = $this->calculateRating($id,$type);
                                $services[$key]->reviews = $this->calculateReview($id,$type);
                                $services[$key]->distance = $service->distance;
                               
                                $day = date("D",strtotime($on_date));
                                $business_schedule = $this->BusinessHoursModel->getWhere(["business_id" => $business_id])->getResultArray();
                                foreach($business_schedule as $timings){
                                   $timing = $timings['timings'];
                                   $obj = json_decode($timing);
                                   
                                   foreach($obj as $value){
                                       if( ($day == $value->day) && ($value->work_status == "0") ){
                                           $filter_services = $services;
                                       }
                                    }
                                }
                            endforeach;
                            
                            $columns = array_column($filter_services, 'distance'); 
                            array_multisort($columns, SORT_ASC, $filter_services);
                        }elseif($type == "1"){
                            foreach($services as $key => $service) :
                                $business_id = $service->business_id;
                                $id =  $service->business_id;
                                $type = '0';
                               
                                $services[$key]->rating = $this->calculateRating($id,$type);
                                $services[$key]->reviews = $this->calculateReview($id,$type);
                                $services[$key]->distance = $service->distance;
                               
                                $day = date("D",strtotime($on_date));
                                $business_schedule = $this->BusinessHoursModel->getWhere(["business_id" => $business_id])->getResultArray();
                                foreach($business_schedule as $timings){
                                   $timing = $timings['timings'];
                                   $obj = json_decode($timing);
                                   
                                   foreach($obj as $value){
                                       if( ($day == $value->day) && ($value->work_status == "0") ){
                                           $filter_services = $services;
                                       }
                                    }
                                }
                            endforeach;
                            
                            $columns = array_column($filter_services, 'rating'); 
                            array_multisort($columns, SORT_DESC, $filter_services);
                        }else{
                            foreach($services as $key => $service) :
                                $business_id = $service->business_id;
                                $id =  $service->business_id;
                                $type = '0';
                               
                                $services[$key]->rating = $this->calculateRating($id,$type);
                                $services[$key]->reviews = $this->calculateReview($id,$type);
                                $services[$key]->distance = $service->distance;
                               
                                $day = date("D",strtotime($on_date));
                                $business_schedule = $this->BusinessHoursModel->getWhere(["business_id" => $business_id])->getResultArray();
                                foreach($business_schedule as $timings){
                                   $timing = $timings['timings'];
                                   $obj = json_decode($timing);
                                   
                                   foreach($obj as $value){
                                       if( ($day == $value->day) && ($value->work_status == "0") ){
                                           $filter_services = $services;
                                       }
                                    }
                                }
                            endforeach;
                            
                            $columns = array_column($filter_services, 'reviews'); 
                            array_multisort($columns, SORT_DESC, $filter_services);
                        } 
                        
                        if(!empty($filter_services)){
                            $response = array("status"=>1, "message"=>"Services found.", "data" => $filter_services);
                        }else{
                            $response = array("status"=>1, "message"=>"No services found!", "data" => []);
                        }
                    }else{
                        if($type == "0"){
                            foreach($services as $key => $service) :
                               $business_id = $service->business_id;
                               $id =  $service->business_id;
                               $type = '0';
                               
                               $services[$key]->rating = $this->calculateRating($id,$type);
                               $services[$key]->reviews = $this->calculateReview($id,$type);
                               $services[$key]->distance = $service->distance;
                            endforeach;
                            
                            $columns = array_column($services, 'distance'); 
                            array_multisort($columns, SORT_ASC, $services);
                        }elseif($type == "1"){
                            foreach($services as $key => $service) :
                               $business_id = $service->business_id;
                               $id =  $service->business_id;
                               $type = '0';
                               
                               $services[$key]->rating = $this->calculateRating($id,$type);
                               $services[$key]->reviews = $this->calculateReview($id,$type);
                               $services[$key]->distance = $service->distance;
                            endforeach;
                            
                            $columns = array_column($services, 'rating');
                            array_multisort($columns, SORT_DESC, $services);
                        }else{
                            foreach($services as $key => $service) :
                               $business_id = $service->business_id;
                               $id =  $service->business_id;
                               $type = '0';
                               
                               $services[$key]->rating = $this->calculateRating($id,$type);
                               $services[$key]->reviews = $this->calculateReview($id,$type);
                               $services[$key]->distance = $service->distance;
                            endforeach;
                            
                            $columns = array_column($services, 'reviews'); 
                            array_multisort($columns, SORT_DESC, $services);
                        }
                        
                        $response = array("status"=>1, "message"=>"Services found.", "data" => $services);
                    }
                }else{
                    $response = array("status"=>0, "message"=>"No Services found!", "data" => NULL);
                }
            }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
        }
        return $this->respond($response); 
    }
    
    public function businessNames(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
           $business_name = $this->request->getVar('business_name');
           
           $business_names = $this->BusinessDetailModel->get_search_services_name($business_name);
           if(!empty($business_names)){
               $response = array("status"=>1, "message"=>"Businesses names found.", "data" => $business_names);
           }else{
               $response = array("status"=>0, "message"=>"Businesses names not found!", "data" => NULL);
           }
       }else{
           $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
       }
       return $this->respond($response); 
    }
    
    public function businessDetails(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
            $business_id = $this->request->getVar('business_id');
            $user_id = $userData['id'];
            
            $get_service_details = $this->BusinessDetailModel->get_business_details($business_id);
            if(!empty($get_service_details)){
                       $business_id = $get_service_details['business_id'];
                       $id = $get_service_details['business_id'];
                       $type = '0';
                      
                       if(!empty($business_id)){
                           $get_service_details['distance'] = $this->calculateDistance($user_id,$business_id);
                           $get_service_details['rating'] = $this->calculateRating($id,$type);
                           $get_service_details['reviews'] = $this->calculateReview($id,$type);
                           
                           $business_about = $this->BusinessDetailsWebsiteInfModel->get_business_about($business_id);
                           if(!empty($business_about)){
                               $string_version = implode(',', $business_about);
                               $get_service_details['what_we_do'] = $string_version;
                           }else{
                               $get_service_details['what_we_do'] = "";
                           }
                           
                           $favourite_status = $this->FavouriteModel->get_favourite_status($business_id,$user_id);
                           if(!empty($favourite_status)){
                               $string_version = implode(',', $favourite_status);
                               $get_service_details['favourite_status'] = $string_version;
                           }else{
                               $get_service_details['favourite_status'] = "";
                           }
                           
                           $get_business_payment_type = $this->BusinessPaymentTypeModel->get_business_payment_type($business_id);
                           if(!empty($get_business_payment_type)){
                               $convert = implode(',',$get_business_payment_type);
                               $get_service_details['payment_type'] = $convert;
                           }else{
                               $get_service_details['payment_type'] = "0";
                           }
                       }
                 
                $response=array("status"=>1,"message"=>"Business Details found.", "data" => $get_service_details);
            }else{
                $response=array("status"=>0,"message"=>"Business Details not found!", "data" =>NULL);
            }
       }else{
           $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
       }
       return $this->respond($response); 
    }
    
    public function businessServicesDetails(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
            $business_id = $this->request->getVar('business_id');
            
            $get_service_details = $this->ServiceCategoryModel->getWhere(["business_id" => $business_id])->getResultArray();
            if(!empty($get_service_details)){
                foreach($get_service_details as $key=>$details) :
                       $service_business_id = $details['business_id'];
                       $service_id = $details['service_id']; 
                       
                       $business_sub_Services = $this->SubServiceModel->getWhere(["service_id" => $service_id,"business_id" => $service_business_id])->getResultArray();
                       if(!empty($business_sub_Services) && !empty($service_business_id)){
                           $get_service_details[$key]['sub_services'] = $business_sub_Services; 
                       }else{
                           $get_service_details[$key]['sub_services'] = []; 
                       }
                endforeach;
                $response=array("status"=>1,"message"=>"Services found.", "data" => $get_service_details);
            }
            else{
              $response=array("status"=>0,"message"=>"Services not found!", "data" =>NULL);
            }
       }else{
           $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
       }
       return $this->respond($response); 
    }
    
    public function businessReviewsDetails(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
            $business_id = $this->request->getVar('business_id');
            
            $get_emp_reviews = $this->RateReviewBusinessEmployeeModel->getWhere(['emp_business_id'=>$business_id])->getResultArray();
            if(!empty($get_emp_reviews)){
                 foreach($get_emp_reviews as $key => $service) :
                       $emp_id = $service['bus_emp_id']; 
                       $user_id = $service['user_id'];
                       $booking_id = $service['booking_id'];
                       $rated_id = $service['id']; 
                       
                       $get_emp_dtl = $this->EmployeeModel->get_review_emp_name($emp_id);
                       if(!empty($get_emp_dtl)){
                           $get_emp_reviews[$key]['emp_dtl'] = $get_emp_dtl;
                       }else{
                            $get_emp_reviews[$key]['emp_dtl'] = [];
                       }
                       
                       $get_user_dtl = $this->UserModel->get_review_user_name($user_id);
                       if(!empty($get_user_dtl)){
                           $get_emp_reviews[$key]['user_dtl'] = $get_user_dtl;
                       }else{
                           $get_emp_reviews[$key]['user_dtl'] = [];
                       }
                       
                       $get_services_name = $this->RatedBookingsServicesModel->get_booking_sub_services($rated_id);
                       if(!empty($get_services_name)){
                           $get_emp_reviews[$key]['sub_services'] = $get_services_name;
                       }else{
                           $get_emp_reviews[$key]['sub_services'] = [];
                       }
                 endforeach;
                 $response=array("status"=>1,"message"=>"Reviews found.", "data" => $get_emp_reviews);
            }else{
            	$response=array("status"=>0,"message"=>"No reviews found!", "data" =>NULL);
            }
       }else{
           $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
       }
       return $this->respond($response); 
    }
    
    public function businessStaffDetails(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
            $business_id = $this->request->getVar('business_id');
            
            $business_staff = $this->EmployeeModel->getWhere(["business_id" => $business_id])->getResultArray();
            if(!empty($business_staff)){
                 foreach($business_staff as $key=>$service) :
                       $id = $service['emp_id'];
                       $type = '1';
                       
                       $business_staff[$key]['emp_rating'] = $this->calculateRating($id,$type);
                 endforeach;
                $response=array("status"=>1,"message"=>"Business Staff found.", "data" => $business_staff);
            }
            else{
              $response=array("status"=>0,"message"=>"Business Staff not found!", "data" =>NULL);
            }
       }else{
           $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
       }
       return $this->respond($response); 
    }
    
     public function businessGallery(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
            $business_id = $this->request->getVar('business_id');
            
            $business_gallery = $this->BusinessPortfolioModel->getWhere(["business_id" => $business_id])->getResultArray();
            if(!empty($business_gallery)){
                $response=array("status"=>1,"message"=>"Business Gallery found.", "data" => $business_gallery);
            }
            else{
              $response=array("status"=>0,"message"=>"No images added to the gallery.", "data" =>NULL);
            }
       }else{
           $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
       }
       return $this->respond($response); 
    }
    
    public function businessAboutDetails(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
            $business_id = $this->request->getVar('business_id');
            
            $business_about = $this->BusinessDetailModel->get_business_about_section_details($business_id);
            if(!empty($business_about)){
                $business_id = $business_about['business_id']; 
                
                $business_website_about = $this->BusinessDetailsWebsiteInfModel->get_business_about($business_id);
                   if(!empty($business_website_about)){
                       $string_version = implode(',', $business_website_about);
                       $business_about['about_us'] = $string_version;
                   }else{
                       $business_about['about_us'] = "";
                   }
                   
                $business_website_email = $this->BusinessDetailsWebsiteInfModel->get_business_email($business_id);
                   if(!empty($business_website_email)){
                       $string_version = implode(',', $business_website_email);
                       $business_about['email'] = $string_version;
                   }else{
                       $business_about['email'] = "";
                   }
                   
                $business_website = $this->BusinessDetailsWebsiteInfModel->get_business_website($business_id);
                   if(!empty($business_website)){
                       $string_version = implode(',', $business_website);
                       $business_about['website'] = $string_version;
                   }else{
                       $business_about['website'] = "";
                   }
                
                $business_schedule = $this->BusinessHoursModel->getWhere(["business_id" => $business_id])->getRowArray();
                $timings = $business_schedule['timings'];
                $obj = json_decode($timings);
                   if(!empty($business_schedule) && !empty($business_id)){
                       $business_about['schedule'] = $obj; 
                   }else{
                       $business_about['schedule'] = []; 
                   }
                   
                $business_amenities = $this->BusinessDetailAdditionalInformationModel->get_business_amenities($business_id);
                   if(!empty($business_amenities)){
                       $string_version = implode(',', $business_amenities);
                       $business_about['amenities'] = $string_version;
                   }else{
                       $business_about['amenities'] = "";
                   }
                   
                $business_cancellation_policy = $this->BusinessDetailAdditionalInformationModel->get_business_cancellation_policy($business_id);
                   if(!empty($business_cancellation_policy)){
                       $string_version = implode(',', $business_cancellation_policy);
                       $business_about['cancellation_policy'] = $string_version;
                   }else{
                       $business_about['cancellation_policy'] = "";
                   }
                       
                 $business_health_safety = $this->BusinessDetailAdditionalInformationModel->get_business_health_safety($business_id);
                 if(!empty($business_health_safety)){
                       $string_version = implode(',', $business_health_safety);
                       $business_about['health_safety'] = $string_version;
                 }else{
                       $business_about['health_safety'] = "";
                 }
                 
                 $business_assigned_category = $this->AssignedBusinessCategoryModel->get_assigned_business_category_name($business_id);
                 if(!empty($business_assigned_category)){
                       $string_version = implode(',', $business_assigned_category);
                       $business_about['business_category'] = $string_version;
                 }else{
                       $business_about['business_category'] = "";
                 }

                $response=array("status"=>1,"message"=>"Business Information found.", "data" => $business_about);
            }
            else{
              $response=array("status"=>0,"message"=>"Business Information not found!", "data" =>NULL);
            }
       }else{
           $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
       }
       return $this->respond($response); 
    }
    
    public function userHome(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
           $user_id = $userData['id'];
           
           if(!empty($user_id)){
               $get_user_dtl =array();
                    $get_bus_categories = $this->BusinessCategoryModel->get_business_categories(); //Categories
                    if(!empty($get_bus_categories)){
                        $get_user_dtl['categories'] = $get_bus_categories;
                    }else{
                        $default = array (
                            "id" => "",
                            "business_category" => ""
                        );
                        $get_user_dtl['categories'] = $default;
                    }
                    
                    $get_upcoming_bookings = $this->AddBookingModel->get_home_upcoming_bookings($user_id); //Bookings
                    if(!empty($get_upcoming_bookings) && !empty($user_id)){
                          $get_user_dtl['bookings'][0]['category'] = "Upcoming Bookings";
                          $get_user_dtl['bookings'][0]['type'] = "upcoming";
                          $get_user_dtl['bookings'][0]['data'] = $get_upcoming_bookings; 
                    }
                    
                    $get_special_offers = $this->AddCouponModel->get_home_coupons(); //Special Offers
                    if($get_special_offers){
                          $get_user_dtl['bookings'][1]['category'] = "Special Offers";
                          $get_user_dtl['bookings'][1]['type'] = "offers";
                          $get_user_dtl['bookings'][1]['data'] = $get_special_offers; 
                    }
                    
                    $get_recommended_services = $this->AdvertisedBusinessModel->get_home_advertised_services(); //Recommended Services
                    if(!empty($get_recommended_services)){
                        foreach($get_recommended_services as $key => $business){
                          $business_id = $business->business_id;
                          
                          $get_recommended_services[$key]->distance = $this->calculateDistance($user_id,$business_id);
                        }
                
                        $columns = array_column($get_recommended_services, 'distance'); //Sort array key in ASC/DESC order
                        array_multisort($columns, SORT_ASC, $get_recommended_services);
                        
                        $get_user_dtl['bookings'][2]['category'] = "Recommended Services"; 
                        $get_user_dtl['bookings'][2]['type'] = "recommended";
                        $get_user_dtl['bookings'][2]['data'] = $get_recommended_services;
                    }
                    
                    $get_today_aval_services = $this->UserModel->get_home_avaltoday_services(); //Today Available Services
                    if(!empty($get_today_aval_services)){
                        foreach($get_today_aval_services as $key => $business){
                          $business_id = $business->business_id;
                          
                          $get_today_aval_services[$key]->distance = $this->calculateDistance($user_id,$business_id);
                        }
                
                        $columns = array_column($get_today_aval_services, 'distance'); //Sort array key in ASC/DESC order
                        array_multisort($columns, SORT_ASC, $get_today_aval_services);
                        
                        $get_user_dtl['bookings'][3]['category'] = "Available Today";
                        $get_user_dtl['bookings'][3]['type'] = "today";
                        $get_user_dtl['bookings'][3]['data'] = $get_today_aval_services;
                    }
                    
                $get_user_dtl['bookings'] =  array_values($get_user_dtl['bookings']);
                $response=array("status"=>1,"message"=>"Details found.", "data" => $get_user_dtl);
           }else{
                $response=array("status"=>0,"message"=>"Details not found!", "data" => NULL);     
           }
       }
       else{
           $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
       }
       return $this->respond($response); 
    }
    
    public function viewAssignedCategories(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $user_id = $userData['id'];
            $category_id = $this->request->getVar('id'); 
            $get_Assigned_categories = $this->AssignedBusinessCategoryModel->getWhere(['bussiness_category_id'=>$category_id])->getResultArray();
            
            if(!empty($get_Assigned_categories)){
                
                foreach($get_Assigned_categories as $key => $categories){
                    $business_id = $categories['business_id'];
                    $id = $categories['business_id'];
                    $type = '0';
                    
                    $get_user_dtl = $this->UserModel->get_user_home_data($business_id);
                    if(!empty($get_user_dtl)){
                       $get_Assigned_categories[$key]['user'] = $get_user_dtl;
                    }else{
                       $get_Assigned_categories[$key]['user'] = []; 
                    }
                    
                    $get_business_info = $this->BusinessDetailModel->get_business_home_data($business_id);
                    if(!empty($get_business_info)){
                       $get_Assigned_categories[$key]['business_details'] = $get_business_info;
                    }else{
                       $get_Assigned_categories[$key]['business_details'] = []; 
                    }
                    
                    $get_Assigned_categories[$key]['distance'] = $this->calculateDistance($user_id,$business_id);
                    $get_Assigned_categories[$key]['rating'] = $this->calculateRating($id,$type);
                    $get_Assigned_categories[$key]['reviews'] = $this->calculateReview($id,$type);
                
                }
                
                $columns = array_column($get_Assigned_categories, 'distance'); //Sort array key in ASC/DESC order
                array_multisort($columns, SORT_ASC, $get_Assigned_categories);
                        
                $response = array("status"=>1, "message"=>"Categories found.", "data" => $get_Assigned_categories);
            }
            else{
                $response = array("status"=>0, "message"=>"Categories not found!", "data" => NULL); 
            }
        }else{
            $response = array("status"=>0, "message"=>"User not found!", "data" => NULL); 
        }
        return $this->respond($response);
    }
    
    public function rateReviewBusinessEmployee(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $rating = $this->request->getVar('rating'); 
            $review = $this->request->getVar('review'); 
            $bus_emp_id = $this->request->getVar('id'); 
            $booking_id = $this->request->getVar('booking_id'); 
            $type = $this->request->getVar('type'); //0=Business,1=Employee
            $created_at = date('Y-m-d H:i:s');
            
            $get_emp_business_id = $this->AddBookingModel->getWhere(['id'=>$booking_id])->getRowArray();
            
            if($type == "0"){
                $insert = ['rating'=>$rating,'review'=>$review,'bus_emp_id'=>$bus_emp_id,'user_id'=>$userData['id'],'type'=>$type,'booking_id'=>$booking_id,'created_at'=>$created_at];
            }else{
                $insert = ['rating'=>$rating,'review'=>$review,'bus_emp_id'=>$bus_emp_id,'user_id'=>$userData['id'],'type'=>$type,'booking_id'=>$booking_id,'created_at'=>$created_at,'emp_business_id'=>$get_emp_business_id['business_id']];
            }
            
            if(!empty($insert)){
                $add = $this->RateReviewBusinessEmployeeModel->save($insert);
                $last_inserted_id = $this->RateReviewBusinessEmployeeModel->insertID();
                $get_booking_services= $this->RatedBookingsServicesModel->get_booking_sub_services_name($booking_id); //Get booking services 
                foreach($get_booking_services as $serve) :
                    $data = array(
                        'sub_service_name' => $serve,
                        'rated_id'     => $last_inserted_id,
                    );
                    $result = $this->RatedBookingsServicesModel->save($data);
                endforeach;
                $response = array("status"=>1, "message"=>"Feedback added. Thanks!", "data" => $add);
            }else{
                $response = array("status"=>0, "message"=>"Feedback not added!", "data" => NULL); 
            }
        }else{
          $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);   
        }
        return $this->respond($response);
    }
    
    public function  viewBusinessBookings(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
           $business_id = $userData['id'];
           $booking_date = $this->request->getVar('date'); //yyyy-mm-dd
           $emp_id = $this->request->getVar('emp_id');
           $booking_type = $this->request->getVar('type'); //4=All,0=Upcoming,1=Completed,2=Cancelled Bookings
           
            if($booking_type == "4"){
               if(empty($emp_id)){
                  $bookings = $this->AddBookingModel->getWhere(["business_id"=>$business_id,"booking_date"=>$booking_date])->getResultArray();
               }
               else{
                  $bookings = $this->AddBookingModel->getWhere(["business_id"=>$business_id,"booking_date"=>$booking_date,'emp_id'=>$emp_id])->getResultArray();
               }
            }elseif($booking_type == "0" || $booking_type == "1" || $booking_type == "2"){
               if(empty($emp_id)){
                  $bookings = $this->AddBookingModel->getWhere(["business_id"=>$business_id,"booking_date"=>$booking_date,'status'=>$booking_type])->getResultArray();
               }else{
                  $bookings = $this->AddBookingModel->getWhere(["business_id"=>$business_id,"booking_date"=>$booking_date,'status'=>$booking_type,'emp_id'=>$emp_id])->getResultArray();
               }
           }else{
               $response=array("status"=>0,"message"=>"No booking found!", "data" => NULL);   
           }
               
           if(!empty($bookings)){
             foreach($bookings as $key=>$service) :
                   $booking_id = $service['id'];
                   $user_id = $service['user_id'];
                   $emp_id = $service['emp_id'];
                   $business_id = $service['business_id'];
                   $booking_id = $service['id'];
                   
                   $get_booking_user_name = $this->UserModel->get_user_dtl_bus($user_id);
                   if(!empty($get_booking_user_name) && !empty($user_id)){
                       $bookings[$key]['user'] = $get_booking_user_name;
                   }else{
                       $bookings[$key]['user'] = []; 
                   }
                   
                   $get_booking_emp_name = $this->EmployeeModel->get_booking_emp_name($emp_id);
                   if(!empty($get_booking_emp_name) && !empty($emp_id)){
                       $bookings[$key]['staff'] = $get_booking_emp_name;
                   }else{
                        $default = array (
                            "emp_id" => "",
                            "emp_first_name" => "",
                            "emp_last_name" => "",
                            "emp_img" => "",
                        );
                        $bookings[$key]['staff'] = $default;
                   }
                   
                   $get_booking_payment_details = $this->AddBookingModel->get_booking_payment_total_amount($user_id,$booking_id);
                    if(!empty($get_booking_payment_details)){
                       $convert = implode(',',$get_booking_payment_details);
                       $bookings[$key]['amount'] = $convert;
                    }else{
                       $bookings[$key]['amount'] = "";
                    }
                   
                   $get_booking_rating = $this->RateReviewBusinessEmployeeModel->get_booking_rating_by_user_to_bus($booking_id,$user_id,$business_id);
                   if(!empty($get_booking_rating)){
                        $bookings[$key]['rating'] = $get_booking_rating['rating'];
                   }else{
                        $bookings[$key]['rating'] = "0";
                   }
                   
                   $booking_sub_Services = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                   if(!empty($booking_sub_Services) && !empty($business_id)){
                       $bookings[$key]['sub_services'] = $booking_sub_Services; 
                   }else{
                       $bookings[$key]['sub_services'] = []; 
                   }
             endforeach;
             $response=array("status"=>1,"message"=>"Bookings found.", "data" => $bookings);
           }else{
               $response=array("status"=>0,"message"=>"No booking found on selected date!", "data" => NULL);   
           }
       }else{
             $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
       }
       return $this->respond($response); 
    }
    
    public function weekMonthBookings(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
           $business_id = $userData['id'];
           $emp_id = $this->request->getVar('emp_id');
           $booking_type = $this->request->getVar('type'); //4=All,0=Upcoming,1=Completed,2=Cancelled Bookings
           $type = $this->request->getVar('booking_type'); //0=Weekly,1=Monthly
           
           $bookings = $this->AddBookingModel->get_week_month_bookings($business_id,$type,$emp_id,$booking_type);
           if(!empty($bookings)){
                 foreach($bookings as $key=>$service) :
                   $booking_id = $service->id;
                   $user_id = $service->user_id;
                   $emp_id = $service->emp_id;
                   $business_id = $service->business_id;
                   
                   $get_booking_user_name = $this->UserModel->get_user_dtl_bus($user_id);
                   if(!empty($get_booking_user_name) && !empty($user_id)){
                       $bookings[$key]->user = $get_booking_user_name;
                   }else{
                       $bookings[$key]->user = []; 
                   }
                   
                   $get_booking_emp_name = $this->EmployeeModel->get_booking_emp_name($emp_id);
                   if(!empty($get_booking_emp_name) && !empty($emp_id)){
                       $bookings[$key]->staff = $get_booking_emp_name;
                   }else{
                       $default = array (
                            "emp_id" => "",
                            "emp_first_name" => "",
                            "emp_last_name" => "",
                            "emp_img" => "",
                        );
                       $bookings[$key]->staff = $get_booking_emp_name;
                    }
                   
                   $get_booking_payment_details = $this->AddBookingModel->get_booking_payment_total_amount($user_id,$booking_id);
                    if(!empty($get_booking_payment_details)){
                       $convert = implode(',',$get_booking_payment_details);
                       $bookings[$key]->amount = $convert;
                    }else{
                       $bookings[$key]->amount = "";
                    }
                   
                   $booking_sub_Services = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                   if(!empty($booking_sub_Services) && !empty($business_id)){
                       $bookings[$key]->sub_services = $booking_sub_Services; 
                   }else{
                       $bookings[$key]->sub_services = []; 
                   }
                   
                   $get_booking_rating = $this->RateReviewBusinessEmployeeModel->get_booking_rating_by_user_to_bus($booking_id,$user_id,$business_id);
                   if(!empty($get_booking_rating)){
                        $bookings[$key]->rating = $get_booking_rating['rating'];
                   }else{
                        $bookings[$key]->rating = "0";
                   }
                endforeach;
                $response=array("status"=>1,"message"=>"Bookings found.", "data" => $bookings);
           }else{
               $response=array("status"=>0,"message"=>"No booking found!", "data" => NULL);   
           }
       }else{
           $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
       }
       return $this->respond($response);
    }
    
    public function viewCustomBusBookings(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
           $business_id = $userData['id'];
           $sdate = $this->request->getVar('start_date');
           $edate = $this->request->getVar('end_date');
           $emp_id = $this->request->getVar('emp_id');
           $booking_type = $this->request->getVar('type'); //4=All,0=Upcoming,1=Completed,2=Cancelled Bookings
           
           if($edate >= $sdate){
               $bookings = $this->AddBookingModel->get_custom_bookings($business_id,$sdate,$edate,$emp_id,$booking_type);
               if(!empty($bookings)){
                        foreach($bookings as $key=>$service) :
                           $booking_id = $service->id;
                           $user_id = $service->user_id;
                           $emp_id = $service->emp_id;
                           $business_id = $service->business_id;
                           
                           $get_booking_user_name = $this->UserModel->get_user_dtl_bus($user_id);
                           if(!empty($get_booking_user_name) && !empty($user_id)){
                               $bookings[$key]->user = $get_booking_user_name;
                           }else{
                               $bookings[$key]->user = []; 
                           }
                           
                           $get_booking_emp_name = $this->EmployeeModel->get_booking_emp_name($emp_id);
                           if(!empty($get_booking_emp_name) && !empty($emp_id)){
                               $bookings[$key]->staff = $get_booking_emp_name;
                           }else{
                               $default = array (
                                    "emp_id" => "",
                                    "emp_first_name" => "",
                                    "emp_last_name" => "",
                                    "emp_img" => "",
                                );
                               $bookings[$key]->staff = $get_booking_emp_name;
                            }
                           
                           $get_booking_payment_details = $this->AddBookingModel->get_booking_payment_total_amount($user_id,$booking_id);
                            if(!empty($get_booking_payment_details)){
                               $convert = implode(',',$get_booking_payment_details);
                               $bookings[$key]->amount = $convert;
                            }else{
                               $bookings[$key]->amount = "";
                            }
                           
                           $booking_sub_Services = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                           if(!empty($booking_sub_Services) && !empty($business_id)){
                               $bookings[$key]->sub_services = $booking_sub_Services; 
                           }else{
                               $bookings[$key]->sub_services = []; 
                           }
                           
                           $get_booking_rating = $this->RateReviewBusinessEmployeeModel->get_booking_rating_by_user_to_bus($booking_id,$user_id,$business_id);
                           if(!empty($get_booking_rating)){
                                $bookings[$key]->rating = $get_booking_rating['rating'];
                           }else{
                                $bookings[$key]->rating = "0";
                           }
                        endforeach;
                        $response=array("status"=>1,"message"=>"Bookings found.", "data" => $bookings);
                    }else{
                        $response=array("status"=>0,"message"=>"No bookings found on selected date!", "data" => NULL);   
                    }
           }else{
               $response=array("status"=>0,"message"=>"End date must be greater than start date!", "data" => NULL);   
           }
       }else{
           $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
       }
       return $this->respond($response); 
    }
    
    public function viewBusinessBookingDetails(){
       $userId = $this->decodeToken();
       $userData = $this->UserModel->get_single_userdata($userId);

       if(!empty($userData)) {
            $booking_id = $this->request->getVar('id'); 
            $booking_discount_amount = $this->request->getVar('discount_amount'); 
            
            $get_booking_details = $this->AddBookingModel->getWhere(['id'=>$booking_id,'business_id'=>$userData['id']])->getRowArray();
                if(!empty($get_booking_details)){
                          $business_id = $get_booking_details['business_id'];
                          $booking_id = $get_booking_details['id'];
                          $emp_id = $get_booking_details['emp_id'];
                          $user_id = $get_booking_details['user_id'];
                          
                          $get_user_dtl = $this->UserModel->get_user_dtl_bus($user_id);
                          if(!empty($get_user_dtl)){
                               $get_booking_details['user'] = $get_user_dtl;
                          }else{
                               $get_booking_details['user'] = []; 
                          }
                          
                          $get_booking_emp_name = $this->EmployeeModel->get_booking_emp_name($emp_id);
                           if(!empty($get_booking_emp_name) && !empty($emp_id)){
                               $get_booking_details['staff'] = $get_booking_emp_name;
                           }else{
                               $get_booking_details['staff'] = []; 
                           }
                           
                           $booking_sub_Services = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                           if(!empty($booking_sub_Services) && !empty($business_id)){
                               $get_booking_details['sub_services'] = $booking_sub_Services; 
                           }else{
                               $get_booking_details['sub_services'] = []; 
                           }
                           
                          if(!empty($business_id)){
                               $get_booking_rating = $this->RateReviewBusinessEmployeeModel->get_booking_rating_by_user_to_bus($booking_id,$user_id,$business_id);
                               if(!empty($get_booking_rating)){
                                    $get_booking_details['business_rating'] = $get_booking_rating['rating'];
                                    $get_booking_details['business_review'] = $get_booking_rating['review'];
                               }else{
                                    $get_booking_details['business_rating'] = "0";
                                    $get_booking_details['business_review'] = "0";
                               }
                           }
                           
                           if(!empty($emp_id)){
                               $get_booking_rating = $this->RateReviewBusinessEmployeeModel->get_booking_rating_by_user_to_emp($booking_id,$user_id,$emp_id);
                               if(!empty($get_booking_rating)){
                                    $get_booking_details['emp_rating'] = $get_booking_rating['rating'];
                                    $get_booking_details['emp_review'] = $get_booking_rating['review'];
                               }else{
                                    $get_booking_details['emp_rating'] = "0";
                                    $get_booking_details['emp_review'] = "0";
                               }
                           }
                            
                            $get_applied_discount_code = $this->AddBookingModel->get_booking_applied_discount_code($user_id,$booking_id);
                            if(!empty($booking_discount_amount)){
                               $promo_code_percentage = implode(',', $get_applied_discount_code);
                               $get_booking_details['promo_code_applied_percentage'] = $promo_code_percentage;
                            }else{
                               $get_booking_details['promo_code_applied_percentage'] = "";
                            }
                           
                           $get_booking_payment_details = $this->AddBookingModel->get_booking_payment_details($user_id,$booking_id);
                            if(!empty($get_booking_payment_details)){
                               $get_booking_details['payment_details'] = $get_booking_payment_details;
                            }else{
                               $default = array (
                                    "amount" => "",
                                    "payment_method_type" => "",
                                    "payment_status" => ""
                                );
                                $get_booking_details['payment_details'] = $default;
                            }
                           
                           $response = array("status"=>1, "message"=>"Booking details found.", "data" => $get_booking_details);
                }else{
                    $response = array("status"=>0, "message"=>"Booking details not found!", "data" => NULL);
                }
       }else{
           $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL); 
       }
       return $this->respond($response);
    }
    
    public function addBusinessClient(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $first_name = $this->request->getVar('first_name'); 
            $last_name = $this->request->getVar('last_name'); 
            $email = $this->request->getVar('email'); 
            $phone_number = $this->request->getVar('phone_number');
            $country_code = $this->request->getVar('country_code');
            
            $data =['first_name'=>$first_name,'last_name'=>$last_name,'email'=>$email,'mobile'=>$phone_number,'country_code'=>$country_code,'user_type'=>'1','bus_emp_client_added_id'=>$userData['id']];
            
            $save_data = $this->UserModel->insert($data);
            $last_inserted_id = $this->UserModel->insertID();
            $get_added_user = $this->UserModel->getWhere(['id'=>$last_inserted_id])->getRowArray();
            if(!empty($get_added_user)){
                $response = array("status"=>1, "message"=>"Client added successfully.", "data" => $get_added_user); 
            }else{
                $response = array("status"=>0, "message"=>"Client not added!", "data" => NULL); 
            }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);   
        }
        return $this->respond($response);
    }
    
    public function getBusinessClients(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            
            $get_clients = $this->UserModel->getWhere(['bus_emp_client_added_id'=>$userData['id'],'user_type'=>'1'])->getResultArray();
            if(!empty($get_clients)){
                $response = array("status"=>1, "message"=>"Clients found.", "data" => $get_clients); 
            }else{
                $response = array("status"=>0, "message"=>"Client not fount!", "data" => NULL); 
            }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);   
        }
        return $this->respond($response);
    }
    
    public function addBusinessBooking(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
		    $business_id = $userData['id'];
		    $client_id = $this->request->getVar('client_id');
		    $emp_id = $this->request->getVar('emp_id');
		    $booking_date = $this->request->getVar('booking_date');
		    $booking_timestamp = strtotime($booking_date);
		    $booking_time = $this->request->getVar('booking_time');
    		$time = time(); 
    		$current_date = date("Y-m-d",$time);
    		$status = '0'; //0=Open
    		$created_at	= date('Y-m-d H:i:s');
    		$type = "1";
    		
    		if($booking_timestamp >= strtotime($current_date)){
    		 if($emp_id == 0){ //Any staff start
    		     $assign_staff = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'status'=>$status])->getResultArray();
    		     if(!empty($assign_staff)){
    		         $staffs = $assign_staff;
    		     }else{
    		         $staffs = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'booking_date >='=>$current_date])->getResultArray();
    		     }
    		    
    		     $staff_ids = array();
                 foreach($staffs as $staff){
                    $staff_ids[] = $staff['emp_id'];
                    
                    $get_free_staffs = $this->EmployeeModel->get_free_staffs($staff_ids,$business_id);
                    if(!empty($get_free_staffs)){
                        foreach($get_free_staffs as $getsid){
                     		$data = [
                    		    'business_id'   => $business_id,
                    			'emp_id'	    => $getsid['emp_id'],
                    			'booking_date'	=> $booking_date,
                    			'booking_time'	=> $booking_time,
                    			'created_at'	=> $created_at,
                    			'status'        => $status,
                    			'user_id'       => $client_id,
                    			'type'          => $type,
                    			'payment_type'  => '0' //In-Shop
                    		];
                            break;
                        }
                    }else{
                        if($staff['booking_time'] != $booking_time){
                     		$data = [
                    		    'business_id'   => $business_id,
                    			'emp_id'	    => $staff['emp_id'],
                    			'booking_date'	=> $booking_date,
                    			'booking_time'	=> $booking_time,
                    			'created_at'	=> $created_at,
                    			'status'        => $status,
                    			'user_id'       => $client_id,
                    			'type'          => $type,
                    			'payment_type'  => '0' //In-Shop
                    		];
                        }
                   }
                }  
    		 }//Any staff end
    		 else{
         		$data = [
        		    'business_id'   => $business_id,
        			'emp_id'	    => $emp_id,
        			'booking_date'	=> $booking_date,
        			'booking_time'	=> $booking_time,
        			'created_at'	=> $created_at,
        			'status'        => $status,
        			'user_id'       => $client_id,
        			'type'          => $type,
        			'payment_type'  => '0' //In-Shop
        		];
    		 }
             
		     $result = $this->AddBookingModel->insert($data);
		     $last_inserted_id = $this->AddBookingModel->insertID();
    		    if(!empty($last_inserted_id)) {
    		        $sub_service_id = array();
    		        $sub_service_id = (explode(",",$this->request->getVar('sub_service_id')));
    		        foreach ($sub_service_id as $row) {              
                            $sub_services['sub_services'] = $row;
                            $get_sub_nam = $this->SubServiceModel->get_sub_service_name($row);
            		        $data = [
                    		    'sub_service_id' => $sub_services,
                    			'booking_id'	 => $last_inserted_id,
                    			'user_id'        => $client_id,
                    			'sub_service_name' => $get_sub_nam['sub_service_name'],
                    		];
            		        $upresult = $this->BookingsServicesModel->insert($data);
                    }
                    $updated_data = $this->AddBookingModel->getWhere(['id'=>$last_inserted_id])->getRowArray();
                    $response=array("status"=>1,"message"=>"Booking added successfully.", "data" => $updated_data);
                }else {
                    $response=array("status"=>0,"message"=>"Booking not added, please try again!");
                }
    		}
    		else{
    		    $response=array("status"=>0,"message"=>"Booking date must be greater than or equal to current date!", "data" => NULL);
    		}
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist.", "data" => NULL);   
        }
        return $this->respond($response); 
    }
    
    public function cancelBusinessBooking(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $business_id= $userData['id'];
            $booking_id = $this->request->getVar('id');
            $booking_reason = $this->request->getVar('write_cancel_reason');
            $current_date = date("Y-m-d");
            
            $get_booking_date = $this->AddBookingModel->getWhere(['id'=>$booking_id])->getRowArray();
            if($get_booking_date['booking_date'] < $current_date){
                $response=array("status"=>0,"message"=>"You cannot cancel bookings on past days!", "data" => NULL); 
            }else{
                $data = ['status' => '2']; // 2=Cancelled Booking
                $result = $this->AddBookingModel->update($booking_id, $data);
                
                if(!empty($result)){
                     $insert = ['booking_id'=>$booking_id,'cancel_reason_text'=>$booking_reason];
                     $cancel_reason = $this->CancelBookingsModel->insert($insert);
		             $response=array("status"=>1,"message"=>"Booking cancelled successfully.", "data" => $cancel_reason);
    		    }else{
    		         $response=array("status"=>0,"message"=>"Booking not cancelled, please try again!", "data" => NULL); 
    		    }
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function modifyBusinessBooking(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $business_id = $userData['id'];
            $booking_id = $this->request->getVar('id');
            $booking_date = $this->request->getVar('booking_date');
            $booking_timestamp = strtotime($booking_date);
            $booking_time = $this->request->getVar('booking_time');
            $emp_id = $this->request->getVar('emp_id');
            $time = time(); 
            $current_date = date("Y-m-d",$time);
            
            if($booking_timestamp >= strtotime($current_date)){
                if($emp_id == 0){ //Any staff start
                    $assign_staff = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'status'=>'0'])->getResultArray();
                     if(!empty($assign_staff)){
                         $staffs = $assign_staff;
                     }else{
                         $staffs = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'booking_date >='=>$current_date])->getResultArray();
                     }
                     
                    $staff_id = array();
                    foreach($staffs as $staff){
                        $staff_ids[] = $staff['emp_id'];
                        
                        $get_free_staffs = $this->EmployeeModel->get_free_staffs($staff_ids,$business_id);
                        if(!empty($get_free_staffs)){
                            foreach($get_free_staffs as $getsid){
                                $data = [
                                    'emp_id'        => $getsid['emp_id'],
                                    'booking_date'  => $booking_date,
                                    'booking_time'  => $booking_time,
                                ];
                                break;
                            }
                        }else{
                            if($staff['booking_time'] != $booking_time){
                                $data = [
                                    'emp_id'        => $staff['emp_id'],
                                    'booking_date'  => $booking_date,
                                    'booking_time'  => $booking_time,
                                ]; 
                            }
                       }
                    }   
                } //Any staff end
                else{  
                    $data = [
                        'emp_id'        => $emp_id,
                        'booking_date'  => $booking_date,
                        'booking_time'  => $booking_time,
                    ];
                }

                $result = $this->AddBookingModel->update($booking_id,$data);
                $sub_service_id = $this->request->getVar('sub_service_id');
                $services = explode(',', $sub_service_id);
                
                $get_booking_id = $this->AddBookingModel->getWhere(['id' => $booking_id])->getRowArray();
                if(!empty($get_booking_id)) {
                    $this->BookingsServicesModel->where(['booking_id' => $get_booking_id['id']])->delete();
                    foreach($services as $serve) :
                         $get_sub_nam = $this->SubServiceModel->get_sub_service_name($serve);
                            $data = array(
                                'sub_service_id' => $serve,
                                'booking_id'     => $get_booking_id['id'],
                                'user_id'     => $get_booking_id['user_id'],
                                'sub_service_name' => $get_sub_nam['sub_service_name'],
                            );
                            $result = $this->BookingsServicesModel->save($data);
                    endforeach;
                    $response=array("status"=>1,"message"=>"Booking modified successfully.", "data" => $result);
                }
                else {
                    $response=array("status"=>0,"message"=>"Booking not modified, please try again!","data" =>NULL);
                }
            }
            else{
                $response=array("status"=>0,"message"=>"Booking date must be greater than or equal to current date!", "data" => NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function rescheduleBusinessBooking(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $business_id= $userData['id'];
            $booking_id = $this->request->getVar('id');
            $booking_date = $this->request->getVar('booking_date');
            $booking_timestamp = strtotime($booking_date);
            $booking_time = $this->request->getVar('booking_time');
            $time = time(); 
            $current_date = date("Y-m-d",$time);
            
            $data = [
                'booking_date'  => $booking_date,
                'booking_time'  => $booking_time,
            ];
            
            if($booking_timestamp >= strtotime($current_date)){
                $result = $this->AddBookingModel->update($booking_id,$data);
                $get_updated_data = $this->AddBookingModel->getWhere(['id'=>$booking_id])->getRowArray();
                if(!empty($result)){
                    $response=array("status"=>1,"message"=>"Booking rescheduled successfully.", "data" => $get_updated_data);
                }else{
                     $response=array("status"=>0,"message"=>"Booking not rescheduled, please try again!","data" =>NULL);
                }
            }
            else{
                $response=array("status"=>0,"message"=>"Booking date must be greater than or equal to current date!", "data" => NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function getModifyRescheduleBusinessBookingDetails(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $booking_id = $this->request->getVar('id');
            $type = $this->request->getVar('type'); //0=Reschedule,1=Modify
            
            $get_booking_id_dtls = $this->AddBookingModel->getWhere(['id' => $booking_id])->getRowArray();
            if(!empty($get_booking_id_dtls)){
                if($type == "1"){
                    $business_id = $get_booking_id_dtls['business_id'];
                    $booking_id = $get_booking_id_dtls['id'];
                    $emp_id = $get_booking_id_dtls['emp_id'];
                    $user_id = $get_booking_id_dtls['user_id'];
                    $id = $get_booking_id_dtls['emp_id'];
                    $type = "1";
                      
                    $get_booking_emp_name = $this->EmployeeModel->get_booking_emp_data($emp_id);
                    if(!empty($get_booking_emp_name) && !empty($emp_id)){
                       $get_booking_emp_name['emp_rating'] = $this->calculateRating($id,$type);
                       $get_booking_id_dtls['staff'] = $get_booking_emp_name;
                    }else{
                       $get_booking_id_dtls['staff'] = []; 
                    }
                       
                    $booking_sub_Services = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                    if(!empty($booking_sub_Services) && !empty($business_id)){
                           $get_booking_id_dtls['sub_services'] = $booking_sub_Services; 
                    }else{
                           $get_booking_id_dtls['sub_services'] = []; 
                    }
                    $response = array("status"=>1, "message"=>"Modify booking details found.", "data" => $get_booking_id_dtls);
                }else{
                    $business_id = $get_booking_id_dtls['business_id'];
                    $booking_id = $get_booking_id_dtls['id'];
                    $emp_id = $get_booking_id_dtls['emp_id'];
                    $user_id = $get_booking_id_dtls['user_id'];
                      
                    $get_booking_emp_name = $this->EmployeeModel->get_booking_emp_data($emp_id);
                    if(!empty($get_booking_emp_name) && !empty($emp_id)){
                       $get_booking_id_dtls['staff'] = $get_booking_emp_name;
                    }else{
                       $get_booking_id_dtls['staff'] = []; 
                    }
                       
                    $get_user_dtl = $this->UserModel->get_user_dtl_bus($user_id);
                    if(!empty($get_user_dtl)){
                           $get_booking_id_dtls['user'] = $get_user_dtl;
                    }else{
                           $get_booking_id_dtls['user'] = []; 
                    }
                      
                    $booking_sub_Services = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                    if(!empty($booking_sub_Services) && !empty($business_id)){
                       $get_booking_id_dtls['sub_services'] = $booking_sub_Services; 
                    }else{
                       $get_booking_id_dtls['sub_services'] = []; 
                    }
                    $response = array("status"=>1, "message"=>"Reschedule booking details found.", "data" => $get_booking_id_dtls);
                }
            }else{
                $response = array("status"=>0, "message"=>"Booking details not found!", "data" => NULL);
            }
        }else{
           $response=array("status"=>0,"message"=>"User not found!", "data" => NULL); 
        }
        return $this->respond($response);
    }
    
    public function searchBusinessClients(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $business_id = $userData['id'];
            $search = $this->request->getVar('search');
            
            $clients = $this->UserModel->get_business_search_clients($search,$business_id);
            if(!empty($clients)){
                $response = array("status"=>1, "message"=>"Client found.", "data" => $clients);
            }else{
                $response = array("status"=>0, "message"=>"No Client found!", "data" => NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function searchBookings(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $business_id = $userData['id'];
            $search = $this->request->getVar('search');
            
            if(!empty($search)){
                $bookings = $this->AddBookingModel->get_searched_bookings($search,$business_id);
                if(!empty($bookings)){
                     foreach($bookings as $key=>$service) :
                           $booking_id = $service->id;
                           $user_id = $service->user_id;
                           $emp_id = $service->emp_id;
                           $business_id = $service->business_id;
                           
                           $get_booking_user_name = $this->UserModel->get_user_dtl_bus($user_id);
                           if(!empty($get_booking_user_name) && !empty($user_id)){
                               $bookings[$key]->user = $get_booking_user_name;
                           }else{
                               $bookings[$key]->user = []; 
                           }
                           
                           $get_booking_emp_name = $this->EmployeeModel->get_booking_emp_name($emp_id);
                           if(!empty($get_booking_emp_name) && !empty($emp_id)){
                               $bookings[$key]->staff = $get_booking_emp_name;
                           }else{
                               $bookings[$key]->staff = []; 
                           }
                           
                           
                           $get_booking_payment_details = $this->AddBookingModel->get_booking_payment_total_amount($user_id,$booking_id);
                            if(!empty($get_booking_payment_details)){
                               $convert = implode(',',$get_booking_payment_details);
                               $bookings[$key]->amount = $convert;
                            }else{
                               $bookings[$key]->amount = "";
                            }
                           
                           $get_booking_rating = $this->RateReviewBusinessEmployeeModel->get_booking_rating_by_user_to_bus($booking_id,$user_id,$business_id);
                           if(!empty($get_booking_rating)){
                                $bookings[$key]->rating = $get_booking_rating['rating'];
                           }else{
                                $bookings[$key]->rating = "0";
                           }
                           
                           $booking_sub_Services = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                           if(!empty($booking_sub_Services) && !empty($business_id)){
                               $bookings[$key]->sub_services = $booking_sub_Services; 
                           }else{
                               $bookings[$key]->sub_services = []; 
                           }
                     endforeach;
                     $temp = array_unique(array_column($bookings, 'id'));
                     $unique_arr = array_intersect_key($bookings, $temp);
                     $new_array = array_values($unique_arr);
                     $response = array("status"=>1, "message"=>"Bookings found.", "data" => $new_array);
                }else{
                    $response = array("status"=>0, "message"=>"No bookings found!", "data" => NULL);
                }
            }else{
                $response = array("status"=>0, "message"=>"Please enter user name, service name or staff name to view bookings!", "data" => NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function businessBookingReceipts(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
    	if(!empty($userData)){
    	    $bus_id = $userData['id'];
    	    
    	    $get_bookings_receipts = $this->PaymentInfoModel->getWhere(['business_id'=>$bus_id])->getResultArray();
    	    if(!empty($get_bookings_receipts)){
    	        foreach($get_bookings_receipts as $key => $receipts){
    	            $emp_id = $receipts['emp_id']; 
    	            
    	            $get_emp_data = $this->EmployeeModel->get_receipt_emp_data($emp_id);
    	            if(!empty($get_emp_data)){
    	                $get_bookings_receipts[$key]['emp_dtl'] = $get_emp_data;
    	            }else{
                        $get_bookings_receipts[$key]['emp_dtl'] = [];
    	            } 
    	        } 
    	        $response=array("status"=>1,"message"=>"Receipts found.", "data" =>$get_bookings_receipts);
    	    }else{
    	        $response=array("status"=>0,"message"=>"No receipts found!", "data" =>NULL);
    	    }
    	}else{
    	    $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
    	}
    	return $this->respond($response);
    }
    
    public function businessBookingReceiptDetails(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
    	if(!empty($userData)){
    	    $business_id = $userData['id'];
    	    $receipt = $this->request->getVar('id');
    	    
    	    $get_receipt_details = $this->PaymentInfoModel->getWhere(['id'=>$receipt,'business_id'=>$business_id])->getRowArray();
    	    if(!empty($get_receipt_details)){
    	            $booking_id = $get_receipt_details['booking_id'];
    	            $user_id = $get_receipt_details['user_id'];
    	            $emp_id = $get_receipt_details['emp_id']; 
    	            
    	            $get_business_img = $this->AddBookingModel->get_receipt_booking_business_img($booking_id);
    	            if(!empty($get_business_img)){
    	                $convert = implode(',',$get_business_img);
    	                $get_receipt_details['business_img'] = $convert;
    	            }else{
                        $get_receipt_details['business_img'] = "";
    	            } 
    	            
    	            $get_business_name = $this->AddBookingModel->get_receipt_booking_business_dtl($booking_id);
    	            if(!empty($get_business_name)){
    	                $get_receipt_details['business_dtl'] = $get_business_name;
    	            }else{
    	                $default = array (
                            "business_name" => "",
                            "business_address_1" => "",
                            "business_address_2" => "",
                            "business_city" => "",
                        );
                        $get_receipt_details['business_dtl'] = $default;
    	            } 
    	            
    	            $get_receipt_details['distance'] = $this->calculateDistance($user_id,$business_id);
    	            
    	            $get_emp_data = $this->EmployeeModel->get_receipt_emp_data($emp_id);
    	            if(!empty($get_emp_data)){
    	                $get_receipt_details['emp_dtl'] = $get_emp_data;
    	            }else{
                        $get_receipt_details['emp_dtl'] = [];
    	            } 
    	            
    	            $get_booking_services = $this->BookingsServicesModel->get_receipt_booking_services($booking_id);
    	            if(!empty($get_booking_services)){
    	                $get_receipt_details['services'] = $get_booking_services;
    	            }else{
                        $default = array (
                            "sub_service_name" => "",
                            "sub_service_price" => "",
                        );
                        $get_receipt_details['services'] = $default;
    	            } 
    	            
    	            $sum=0;
    	            foreach($get_booking_services as $keys => $services_total){
    	                $service_total = $services_total['sub_service_price'];
    	                $sum=$sum+$service_total;
    	                $string = (string)$sum;
    	            }
    	            if(!empty($get_booking_services)){
    	                $get_receipt_details['service_total'] = $string;
    	            }else{
    	                $get_receipt_details['service_total'] = '';
    	            }
    	            
    	            $get_booking_tip = $this->AddBookingModel->get_booking_tip($booking_id);
    	            if(!empty($get_booking_tip)){
    	                $convert = implode(',',$get_booking_tip);
    	                $get_receipt_details['tip'] = $convert;
    	            }else{
                        $get_receipt_details['tip'] = "";
    	            } 
    	            
    	            $get_booking_tax = $this->AddBookingModel->get_booking_tax($booking_id);
    	            if(!empty($get_booking_tax)){
    	                $convert = implode(',',$get_booking_tax);
    	                $get_receipt_details['tax'] = $convert;
    	            }else{
                        $get_receipt_details['tax'] = "";
    	            } 
    	            
    	            $response=array("status"=>1,"message"=>"Receipts details found.", "data" =>$get_receipt_details);
    	    }else{
    	        $response=array("status"=>0,"message"=>"Receipt details not found!", "data" => NULL);
    	    }
    	}else{
    	    $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
    	}
    	return $this->respond($response);
    }
    
    public function analytics(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            $business_id = $userData['id'];
            $type = $this->request->getVar('type'); //0=This Month,1=3 Months,2=6 Months,3=Annual
            
            if($type == "0"){
                $type = 0;
            }elseif($type == "1"){
                $type = 1;
            }elseif($type == "2"){
                $type = 2;
            }else{
                $type = 3;
            }
            
             // Total Revenue start
                    $get_total_revenue = $this->PaymentInfoModel->get_total_revenue($business_id,$type);
                    if(!empty($get_total_revenue)){
                        $booking_total=0;
                        foreach($get_total_revenue as $total){
                            $booking_total += $total->amount;
                        }
                        $total_revenue = (string)$booking_total;
                    }else{
                        $total_revenue = "";
                    }
                //Total Revenue end
                
                //Earning by staff start
                    $get_earning_by_staff = $this->PaymentInfoModel->get_earning_by_staff($business_id,$type);
                    if(!empty($get_earning_by_staff)){
                        foreach($get_earning_by_staff as $key => $staffs_earning){
                            $emp_id = $staffs_earning->emp_id;
                            
                            $get_staffs = $this->PaymentInfoModel->get_earning_by_staff_emps_data($business_id,$emp_id,$type);
                            $earning = 0;
                            foreach($get_staffs as $earnings){
                                $earning += $earnings->amount;
                            }
                            if(!empty($get_staffs)){
                                $get_earning_by_staff[$key]->total_earning = (string)$earning;
                            }else{
                                $get_earning_by_staff[$key]->total_earning = [];
                            }
                            
                            $get_staff_clients_count = $this->PaymentInfoModel->get_staff_appointments_clients_count($business_id,$emp_id,$type);
                            if(!empty($get_staff_clients_count)){
                                $get_earning_by_staff[$key]->clients = (string)$get_staff_clients_count;
                            }else{
                                $get_earning_by_staff[$key]->clients = [];
                            }
                        }
                    }else{
                        $get_earning_by_staff = [];
                    }
                //Earning by staff end
                
               //Earning overtime start
                 $get_earning_overtime = $this->PaymentInfoModel->get_earning_overtime($business_id);
                 if(empty($get_earning_overtime)){
                     $get_earning_overtime = [];
                 }
               //Earning overtime end
               
               //No. of Clients by Staff start
                $get_clients_by_staff = $this->PaymentInfoModel->get_earning_by_staff($business_id,$type);
                if(!empty($get_clients_by_staff)){
                    foreach($get_clients_by_staff as $key => $staffs_clients){
                        $emp_id = $staffs_clients->emp_id;
                        
                        $get_staff_clients_count = $this->PaymentInfoModel->get_staff_appointments_clients_count($business_id,$emp_id,$type);
                        if(!empty($get_staff_clients_count)){
                            $get_clients_by_staff[$key]->clients = (string)$get_staff_clients_count;
                        }else{
                            $get_clients_by_staff[$key]->clients = [];
                        }
                    }
                }else{
                    $get_clients_by_staff = [];
                }
                //No. of Clients by Staff end
                
                //No. of Appointments by Staff start
                    $get_appointments_by_staff = $this->PaymentInfoModel->get_earning_by_staff($business_id,$type);
                    if(!empty($get_appointments_by_staff)){
                        foreach($get_appointments_by_staff as $key => $staffs_appointments){
                            $emp_id = $staffs_appointments->emp_id;
                            
                            $get_appointments_count = $this->PaymentInfoModel->get_staff_appointments_clients_count($business_id,$emp_id,$type);
                            if(!empty($get_appointments_count)){
                                $get_appointments_by_staff[$key]->appointments = (string)$get_appointments_count;
                            }else{
                                $get_appointments_by_staff[$key]->appointments = [];
                            }
                        }
                    }else{
                        $get_appointments_by_staff = [];
                    }
                //No. of Appointments by Staff end
            $response = array("status" => 1,"message" =>"Success.","total_revenue_generated"=>$total_revenue,"earning_by_staff"=>$get_earning_by_staff,"earning_overtime"=>$get_earning_overtime,"clients_by_staff"=>$get_clients_by_staff,"appointments_by_staff"=>$get_appointments_by_staff);
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function analyticsDateRange(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            $business_id = $userData['id'];
            $time = time(); 
            $date = date("Y-m-d",$time);
            $start_date = $this->request->getVar('start_date');
            $end_date = $this->request->getVar('end_date');
            $type = $this->request->getVar('type'); //0=This Month,1=3 Months,2=6 Months,3=Annual
            
            if($type == "0"){
                $type = 0;
            }elseif($type == "1"){
                $type = 1;
            }elseif($type == "2"){
                $type = 2;
            }else{
                $type = 3;
            }
            
            // Total Revenue start
                $get_total_revenue = $this->PaymentInfoModel->get_total_revenue_custom($business_id,$start_date,$end_date,$type);
                if(!empty($get_total_revenue)){
                    $booking_total=0;
                    foreach($get_total_revenue as $total){
                        $booking_total += $total->amount;
                    }
                    $total_revenue = (string)$booking_total;
                }else{
                    $total_revenue = "";
                }
            //Total Revenue end
            
            //Earning by staff start
                $get_earning_by_staff = $this->PaymentInfoModel->get_earning_by_staff_custom($business_id,$type,$start_date,$end_date);
                if(!empty($get_earning_by_staff)){
                    foreach($get_earning_by_staff as $key => $staffs_earning){
                        $emp_id = $staffs_earning->emp_id;
                        
                        $get_staffs = $this->PaymentInfoModel->get_earning_by_staff_emps_data_custom($business_id,$start_date,$end_date,$type,$emp_id);
                        $earning = 0;
                        foreach($get_staffs as $earnings){
                            $earning += $earnings->amount;
                        }
                        if(!empty($get_staffs)){
                            $get_earning_by_staff[$key]->total_earning = (string)$earning;
                        }else{
                            $get_earning_by_staff[$key]->total_earning = [];
                        }
                        
                        $get_staff_clients_count = $this->PaymentInfoModel->get_staff_appointments_clients_count_custom($business_id,$emp_id,$type,$start_date,$end_date);
                        if(!empty($get_staff_clients_count)){
                            $get_earning_by_staff[$key]->clients = (string)$get_staff_clients_count;
                        }else{
                            $get_earning_by_staff[$key]->clients = [];
                        }
                    }
                }else{
                    $get_earning_by_staff = [];
                }
            //Earning by staff end
            
            //Earning overtime start
             $get_earning_overtime = $this->PaymentInfoModel->get_earning_overtime($business_id);
             if(empty($get_earning_overtime)){
                     $get_earning_overtime = [];
             }
           //Earning overtime end
           
           //No. of Clients by Staff start
                $get_clients_by_staff = $this->PaymentInfoModel->get_earning_by_staff_custom($business_id,$type,$start_date,$end_date);
                if(!empty($get_clients_by_staff)){
                    foreach($get_clients_by_staff as $key => $staffs_clients){
                        $emp_id = $staffs_clients->emp_id;
                        
                        $get_staff_clients_count = $this->PaymentInfoModel->get_staff_appointments_clients_count_custom($business_id,$emp_id,$type,$start_date,$end_date);
                        if(!empty($get_staff_clients_count)){
                            $get_clients_by_staff[$key]->clients = (string)$get_staff_clients_count;
                        }else{
                            $get_clients_by_staff[$key]->clients = [];
                        }
                    }
                }else{
                    $get_clients_by_staff = [];
                }
          //No. of Clients by Staff end
          
         //No. of Appointments by Staff start
                $get_appointments_by_staff = $this->PaymentInfoModel->get_earning_by_staff_custom($business_id,$type,$start_date,$end_date);
                if(!empty($get_appointments_by_staff)){
                    foreach($get_appointments_by_staff as $key => $staffs_appointments){
                        $emp_id = $staffs_appointments->emp_id;
                        
                        $get_appointments_count = $this->PaymentInfoModel->get_staff_appointments_clients_count_custom($business_id,$emp_id,$type,$start_date,$end_date);
                        if(!empty($get_appointments_count)){
                            $get_appointments_by_staff[$key]->appointments = (string)$get_appointments_count;
                        }else{
                            $get_appointments_by_staff[$key]->appointments = [];
                        }
                    }
                }else{
                    $get_appointments_by_staff = [];
                }
         //No. of Appointments by Staff end
        
            $response = array("status" => 1,"message" =>"Success.","total_revenue_generated"=>$total_revenue,"earning_by_staff"=>$get_earning_by_staff,"earning_overtime"=>$get_earning_overtime,"clients_by_staff"=>$get_clients_by_staff,"appointments_by_staff"=>$get_appointments_by_staff);
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function advertisementExpiration(){
        $expired_ads = $this->AdvertisedBusinessModel->get_expired_ads();
        
        if(!empty($expired_ads)){
            $data = ['status'=>'0'];
            foreach($expired_ads as $ads){
                $update_advertisement = $this->AdvertisedBusinessModel->update($ads->id,$data);
                
                if(!empty($update_advertisement)){
                    $response=array("status"=>1,"message"=>"Advertisement expired.", "data" => $update_advertisement);
                }else{
                    $response=array("status"=>0,"message"=>"Business not expired!", "data" => NULL);
                }
            }
        }else{
            $response=array("status"=>0,"message"=>"No expired advertisement found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function createPayForAdvertisement(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
                //Ad. creation params
                $address = $this->request->getVar('address'); 
                $radius = $this->request->getVar('radius'); 
                $lat = $this->request->getVar('lat'); 
                $long = $this->request->getVar('long'); 
                $amount = $this->request->getVar('amount'); 
                $duration = $this->request->getVar('duration'); 
                $created_at	= date('Y-m-d');
                $expired_at = date('Y-m-d', strtotime($created_at. '+' .$duration. 'days')); 
                
                $data = [
                    'business_id' => $userData['id'],
                    'latitude'    => $lat,
                    'longitude'   => $long,
                    'address'     => $address,
                    'amount'      => $amount,
                    'duration'    => $duration,
                    'radius'      => $radius,
                    'status'      => "1", //1=Active,0=Expired
                    'created_at'  => $created_at,
                    'expired_at'  => $expired_at
                ];
                
                //Payment params.
                $card_id = $this->request->getVar('card_id');
                $user_name = $userData['first_name'];
                $user_email = $userData['email'];
                date_default_timezone_set('UTC');
                $utcDateTime = date('Y-m-d H:i:s');
                $utcOnlyDate = date('Y-m-d');
                
                //Stripe Secret Key
                $stripesecretKey = $this->get_stripe_secret_key();
                $stripe = new \Stripe\StripeClient($stripesecretKey);
                
                //Create Customer
                $customer = $stripe->customers->create([
                    'email' => $user_email,
                    'name' => $user_name,
                ]);
                
                //Charge Customer
                $process_payment = $stripe->paymentIntents->create([
                    'amount' => 100 * $amount,
                    'currency' => 'USD',
                    'payment_method_types' => ['card'],
                    'customer' => $customer->id,
                    'confirmation_method' => 'manual',
                    'confirm' => true,
                    'payment_method_data' => [
                        'type' => 'card',
                        'card' => [
                            'token' => $this->request->getVar('stripeToken'),
                        ]
                    ],
                    "description" => "Payment for Advertisement",
                ]);
        
                //Check Payment Status
                if(!empty($process_payment->id) && !empty($data)){
                     $this->AdvertisedBusinessModel->insert($data);
                     $lastinsertID = $this->AdvertisedBusinessModel->getInsertID();
            
                     $get_card_number = $this->CardModel->getWhere(['id'=>$card_id])->getRowArray(); //Get User Card Number
                     
                     // Insert transaction details
                     $transactions   = array( 
                        'transaction_id' => $process_payment->id,
                        'source'        => 'stripe', 
                        'amount'        => $amount,
                        'advertisement_id'    => $lastinsertID, 
                        'pay_for'       => 'advertisement',
                        'created_at'    => $utcDateTime,
                        'payment_method_type' => $process_payment->payment_method_types,
                        'name'     => $user_name,
                        'email'    => $user_email,
                        'card_number'   => $get_card_number['card_number'],
                        'payment_status' => 'paid',
                        'business_id'    => $userData['id'],
                        'payment_date'   => $utcOnlyDate,
                     );
                    $this->AdvertisedBusinessPaymentModel->insert($transactions);
                    $get_ad = $this->AdvertisedBusinessModel->getWhere(['id'=>$lastinsertID])->getRowArray();
                    
                    $response=array("status"=>1,"message"=>"Advertisement created and Payment done sucessfully.", "data" =>$get_ad);
                }else{
                    $response=array("status"=>0,"message"=>"Advertisement not created, please try again!", "data" =>NULL);
                }
            }else{
                $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
            }
        return $this->respond($response);
    }
    
    public function createAdAgain(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            //Ad. creation params
            $address = $this->request->getVar('address'); 
            $radius = $this->request->getVar('radius'); 
            $lat = $this->request->getVar('lat'); 
            $long = $this->request->getVar('long'); 
            $amount = $this->request->getVar('amount'); 
            $duration = $this->request->getVar('duration'); 
            $created_at = date('Y-m-d');
            $expired_at = date('Y-m-d', strtotime($created_at. '+' .$duration. 'days')); 
            $ad_id = $this->request->getVar('id');
            
            $data = [
                'business_id' => $userData['id'],
                'latitude'    => $lat,
                'longitude'   => $long,
                'address'     => $address,
                'amount'      => $amount,
                'duration'    => $duration,
                'radius'      => $radius,
                'status'      => "1", //1=Active,0=Expired
                'created_at'  => $created_at,
                'expired_at'  => $expired_at
            ];
            
            //Payment params.
            $card_id = $this->request->getVar('card_id');
            $user_name = $userData['first_name'];
            $user_email = $userData['email'];
            date_default_timezone_set('UTC');
            $utcDateTime = date('Y-m-d H:i:s');
            $utcOnlyDate = date('Y-m-d');
            
            //Stripe Secret Key
            $stripe = new \Stripe\StripeClient('sk_test_51MdmOlJJAF7tzFRKLM6IGH7mviZjTXPm76J9lH2m9ua56Q8RQ7WiDdaPQTxGOos4TkU1pLbcu8ZZujKy0TL86i6z00C6KmbA3i');
        
            /*$token  = $stripe->tokens->create([
                'card' => [
                    'number'    => '4242 4242 4242 4242',
                    'exp_month' => '12',
                    'exp_year'  => '25',
                    'cvc'       => '789',
                ]
            ]);*/
            
            //Create Customer
            $customer = $stripe->customers->create([
                'email' => $user_email,
                'name' => $user_name,
            ]);
            
            //Charge Customer
            $process_payment = $stripe->paymentIntents->create([
                'amount' => 100 * $amount,
                'currency' => 'USD',
                'payment_method_types' => ['card'],
                'customer' => $customer->id,
                'confirmation_method' => 'manual',
                'confirm' => true,
                'payment_method_data' => [
                    'type' => 'card',
                    'card' => [
                        'token' => $this->request->getVar('stripeToken'),
                    ]
                ],
                "description" => "Payment for Advertisement",
            ]);
    
            //Check Payment Status
            if(!empty($process_payment->id) && !empty($data)){
                 $this->AdvertisedBusinessModel->update($ad_id,$data);
        
                 $get_card_number = $this->CardModel->getWhere(['id'=>$card_id])->getRowArray(); //Get User Card Number
                 
                 // Insert transaction details
                 $transactions   = array( 
                    'transaction_id' => $process_payment->id,
                    'source'        => 'stripe', 
                    'amount'        => $amount,
                    'advertisement_id'    => $ad_id, 
                    'pay_for'       => 'advertisement',
                    'created_at'    => $utcDateTime,
                    'payment_method_type' => $process_payment->payment_method_types,
                    'name'     => $user_name,
                    'email'    => $user_email,
                    'card_number'   => $get_card_number['card_number'],
                    'payment_status' => 'paid',
                    'business_id'    => $userData['id'],
                    'payment_date'   => $utcOnlyDate,
                 );
                $this->AdvertisedBusinessPaymentModel->update($ad_id,$transactions);
                $get_ad = $this->AdvertisedBusinessModel->getWhere(['id'=>$ad_id])->getRowArray();
                
                $response=array("status"=>1,"message"=>"Advertisement created again and Payment done sucessfully.", "data" =>$get_ad);
            }else{
                $response=array("status"=>0,"message"=>"Advertisement not created, please try again!", "data" =>NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function advertisementListing(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $get_ads = $this->AdvertisedBusinessModel->getWhere(['business_id'=>$userData['id']])->getResultArray();
            if(!empty($get_ads)){
                foreach($get_ads as $key => $ads){
                    $id = $ads['id'];
                    
                    $get_bus_dtl = $this->AdvertisedBusinessModel->get_advertised_business_dtl($id);
                    if(!empty($get_bus_dtl)){
                        $get_ads[$key]['business_dtl'] = $get_bus_dtl;
                    }else{
                        $get_ads[$key]['business_dtl'] = [];
                    }
                    
                    $get_payment_dtl = $this->AdvertisedBusinessModel->get_advertised_business_payment_dtl($id);
                    if(!empty($get_payment_dtl)){
                        $get_ads[$key]['payment_dtl'] = $get_payment_dtl;
                    }else{
                        $get_ads[$key]['payment_dtl'] = [];
                    }
                }
                $response=array("status"=>1,"message"=>"Advertisement found.", "data" =>$get_ads);
            }else{
                $response=array("status"=>0,"message"=>"No advertisement found!", "data" =>NULL); 
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function clientBookingsDetails(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $business_id = $userData['id'];
            $client_id = $this->request->getVar('id');
            
            $get_cilent_dtl = $this->UserModel->getWhere(['id'=>$client_id,'bus_emp_client_added_id'=>$userData['id']])->getRowArray();
            if(!empty($get_cilent_dtl)){
                    $earning = $this->PaymentInfoModel->get_business_client_earning($business_id,$client_id);
                    if(!empty($earning)){
                        $get_cilent_dtl['earnings_from_client'] = $earning;
                    }else{
                        $get_cilent_dtl['earnings_from_client'] = [];
                    }
                    
                    $all_bookings = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'user_id'=>$client_id])->getResultArray();
                    if(!empty($all_bookings)){
                        foreach($all_bookings as $key => $bookings){
                            $booking_id = $bookings['id'];
                            $user_id = $bookings['user_id'];
                            $emp_id = $bookings['emp_id'];
                            
                            $all_bookings[$key]['staff'] = $this->EmployeeModel->get_booking_emp_name($emp_id);
                            $all_bookings[$key]['sub_services'] = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                            $amount = $this->AddBookingModel->get_booking_payment_total_amount($user_id,$booking_id);
                            $all_bookings[$key]['amount'] = implode(',',$amount);
                            
                            $get_cilent_dtl['all_bookings'] = $all_bookings;
                        }
                    }else{
                        $get_cilent_dtl['all_bookings'] = [];
                    }
                    
                    
                    $upcoming_bookings = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'user_id'=>$client_id,'status'=>'0'])->getResultArray();
                    if(!empty($upcoming_bookings)){
                        foreach($upcoming_bookings as $key => $bookings){
                            $booking_id = $bookings['id'];
                            $user_id = $bookings['user_id'];
                            $emp_id = $bookings['emp_id'];
                            
                            $upcoming_bookings[$key]['staff'] = $this->EmployeeModel->get_booking_emp_name($emp_id);
                            $upcoming_bookings[$key]['sub_services'] = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                            $amount = $this->AddBookingModel->get_booking_payment_total_amount($user_id,$booking_id);
                            $upcoming_bookings[$key]['amount'] = implode(',',$amount);
                            
                            $get_cilent_dtl['upcoming_bookings'] = $upcoming_bookings;
                        }
                    }else{
                        $get_cilent_dtl['upcoming_bookings'] = [];
                    }
                    
                    $completed_bookings = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'user_id'=>$client_id,'status'=>'1'])->getResultArray();
                    if(!empty($completed_bookings)){
                        foreach($completed_bookings as $key => $bookings){
                            $booking_id = $bookings['id'];
                            $user_id = $bookings['user_id'];
                            $emp_id = $bookings['emp_id'];
                            
                            $completed_bookings[$key]['staff'] = $this->EmployeeModel->get_booking_emp_name($emp_id);
                            $completed_bookings[$key]['sub_services'] = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                            $amount = $this->AddBookingModel->get_booking_payment_total_amount($user_id,$booking_id);
                            $completed_bookings[$key]['amount'] = implode(',',$amount);
                            
                            $get_cilent_dtl['completed_bookings'] = $completed_bookings;
                        }
                    }else{
                        $get_cilent_dtl['completed_bookings'] = [];
                    }
                    
                    $cancelled_bookings = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'user_id'=>$client_id,'status'=>'2'])->getResultArray();
                    if(!empty($cancelled_bookings)){
                        foreach($cancelled_bookings as $key => $bookings){
                            $booking_id = $bookings['id'];
                            $user_id = $bookings['user_id'];
                            $emp_id = $bookings['emp_id'];
                            
                            $cancelled_bookings[$key]['staff'] = $this->EmployeeModel->get_booking_emp_name($emp_id);
                            $cancelled_bookings[$key]['sub_services'] = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                            $amount = $this->AddBookingModel->get_booking_payment_total_amount($user_id,$booking_id);
                            $cancelled_bookings[$key]['amount'] = implode(',',$amount);
                            
                            $get_cilent_dtl['cancelled_bookings'] = $cancelled_bookings;
                        }
                    }else{
                        $get_cilent_dtl['cancelled_bookings'] = [];
                    }
                    
                    $in_process_bookings = $this->AddBookingModel->getWhere(['business_id'=>$business_id,'user_id'=>$client_id,'status'=>'6'])->getResultArray();
                    if(!empty($in_process_bookings)){
                        foreach($in_process_bookings as $key => $bookings){
                            $booking_id = $bookings['id'];
                            $user_id = $bookings['user_id'];
                            $emp_id = $bookings['emp_id'];
                            
                            $in_process_bookings[$key]['staff'] = $this->EmployeeModel->get_booking_emp_name($emp_id);
                            $in_process_bookings[$key]['sub_services'] = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                            $amount = $this->AddBookingModel->get_booking_payment_total_amount($user_id,$booking_id);
                            $in_process_bookings[$key]['amount'] = implode(',',$amount);
                            
                            $get_cilent_dtl['in_process_bookings'] = $in_process_bookings;
                        }
                    }else{
                        $get_cilent_dtl['in_process_bookings'] = [];
                    }
                    
                    $response=array("status"=>1,"message"=>"Client bookings details found.", "data" => $get_cilent_dtl); 
            }else{
                    $response=array("status"=>0,"message"=>"Client bookings details not found!", "data" => NULL);  
            }
        }else{
           $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);   
        }
        return $this->respond($response);
    }
    
    public function addEmployeeClient() {
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $first_name = $this->request->getVar('first_name'); 
            $last_name = $this->request->getVar('last_name'); 
            $email = $this->request->getVar('email'); 
            $phone_number = $this->request->getVar('phone_number');
            $country_code = $this->request->getVar('country_code');
            
            $data =['first_name'=>$first_name,'last_name'=>$last_name,'email'=>$email,'mobile'=>$phone_number,'bus_emp_client_added_id'=>$userData['emp_id'],'country_code'=>$country_code];
            
            $save_data = $this->UserModel->insert($data);
            if(!empty($save_data)){
                $response = array("status"=>1, "message"=>"Client added successfully.", "data" => $save_data); 
            }else{
                $response = array("status"=>0, "message"=>"Client not added!", "data" => NULL); 
            }
        }else {
            $response = array("status"=>0, "message"=>"User not found", "data" => NULL);
        }  
        return $this->respond($response);
    }
    
    public function getEmployeeClients() {
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)) {
            $get_clients = $this->UserModel->getWhere(['bus_emp_client_added_id'=>$userData['emp_id']])->getResultArray();
            if(!empty($get_clients)){
                $response = array("status"=>1, "message"=>"Clients found.", "data" => $get_clients); 
            }else{
                $response = array("status"=>0, "message"=>"Client not fount!", "data" => NULL); 
            }
        }else {
            $response = array("status"=>0, "message"=>"User not found", "data" => NULL);
        }  
        return $this->respond($response);
    }
    
    public function viewEmployeeBookings(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $emp_id = $userData['emp_id'];
            $booking_date = $this->request->getVar('date');
            $booking_type = $this->request->getVar('type'); //4=All,0=Upcoming,1=Completed,2=Cancelled Bookings
            
            if($booking_type == "4"){
                $bookings = $this->AddBookingModel->getWhere(["emp_id"=>$emp_id,"booking_date"=>$booking_date])->getResultArray();
            }elseif($booking_type == "0" || $booking_type == "1" || $booking_type == "2"){
                $bookings = $this->AddBookingModel->getWhere(["emp_id"=>$emp_id,"booking_date"=>$booking_date,'status'=>$booking_type])->getResultArray();
            }else{
                $response=array("status"=>0,"message"=>"No booking found on selected date!", "data" => NULL);
            }
            
            if(!empty($bookings)){
                 foreach($bookings as $key=>$service) :
                       $booking_id = $service['id'];
                       $user_id = $service['user_id'];
                       $emp_id = $service['emp_id'];
                       $business_id = $service['business_id'];
                       
                       $get_booking_user_name = $this->UserModel->get_user_dtl_bus($user_id);
                       if(!empty($get_booking_user_name) && !empty($user_id)){
                           $bookings[$key]['user'] = $get_booking_user_name;
                       }else{
                           $bookings[$key]['user'] = []; 
                       }
                       
                       $get_booking_payment_details = $this->AddBookingModel->get_booking_payment_total_amount($user_id,$booking_id);
                        if(!empty($get_booking_payment_details)){
                           $convert = implode(',',$get_booking_payment_details);
                           $bookings[$key]['amount'] = $convert;
                        }else{
                           $bookings[$key]['amount'] = "";
                        }
                       
                       $booking_sub_Services = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                       if(!empty($booking_sub_Services) && !empty($emp_id)){
                           $bookings[$key]['sub_services'] = $booking_sub_Services; 
                       }else{
                           $bookings[$key]['sub_services'] = []; 
                       }
                 endforeach;
                 $response=array("status"=>1,"message"=>"Bookings found.", "data" => $bookings);
           }else{
               $response=array("status"=>0,"message"=>"No booking found on selected date!", "data" => NULL);   
           }
        }else{
            $response = array("status"=>0, "message"=>"User not found", "data" => NULL);
        }  
        return $this->respond($response);
    }
    
    public function empWeekMonthBookings(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $emp_id = $userData['emp_id'];
            $booking_type = $this->request->getVar('type'); //4=All,0=Upcoming,1=Completed,2=Cancelled Bookings
            $type = $this->request->getVar('booking_type'); //0=Weekly,1=Monthly
            
            $bookings = $this->AddBookingModel->get_emp_week_month_bookings($type,$emp_id,$booking_type);
            if(!empty($bookings)){
                foreach($bookings as $key=>$service) :
                   $booking_id = $service->id;
                   $user_id = $service->user_id;
                   $emp_id = $service->emp_id;
                   $business_id = $service->business_id;
                   
                   $get_booking_user_name = $this->UserModel->get_user_dtl_bus($user_id);
                   if(!empty($get_booking_user_name) && !empty($user_id)){
                       $bookings[$key]->user = $get_booking_user_name;
                   }else{
                       $bookings[$key]->user = []; 
                   }
                   
                   $get_booking_payment_details = $this->AddBookingModel->get_booking_payment_total_amount($user_id,$booking_id);
                    if(!empty($get_booking_payment_details)){
                       $convert = implode(',',$get_booking_payment_details);
                       $bookings[$key]->amount = $convert;
                    }else{
                       $bookings[$key]->amount = "";
                    }
                   
                   $booking_sub_Services = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                   if(!empty($booking_sub_Services) && !empty($emp_id)){
                       $bookings[$key]->sub_services = $booking_sub_Services; 
                   }else{
                       $bookings[$key]->sub_services = []; 
                   }
                endforeach;
                $response=array("status"=>1,"message"=>"Bookings found.", "data" => $bookings);
            }else{
                    $response=array("status"=>0,"message"=>"No bookings found!", "data" => NULL);   
            }
        }else{
            $response = array("status"=>0, "message"=>"User not found", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function viewCusEmpBookings(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $emp_id = $userData['emp_id'];
            $sdate = $this->request->getVar('start_date');
            $edate = $this->request->getVar('end_date');
            $booking_type = $this->request->getVar('type');
            
            if($edate >= $sdate){
               $bookings = $this->AddBookingModel->get_custom_bookings_emp($emp_id,$sdate,$edate,$booking_type);
               if(!empty($bookings)){
                        foreach($bookings as $key=>$service) :
                           $booking_id = $service->id;
                           $user_id = $service->user_id;
                           $emp_id = $service->emp_id;
                           $business_id = $service->business_id;
                           
                           $get_booking_user_name = $this->UserModel->get_user_dtl_bus($user_id);
                           if(!empty($get_booking_user_name) && !empty($user_id)){
                               $bookings[$key]->user = $get_booking_user_name;
                           }else{
                               $bookings[$key]->user = []; 
                           }
                           
                           $get_booking_payment_details = $this->AddBookingModel->get_booking_payment_total_amount($user_id,$booking_id);
                            if(!empty($get_booking_payment_details)){
                               $convert = implode(',',$get_booking_payment_details);
                               $bookings[$key]->amount = $convert;
                            }else{
                               $bookings[$key]->amount = "";
                            }
                           
                           $booking_sub_Services = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                           if(!empty($booking_sub_Services) && !empty($emp_id)){
                               $bookings[$key]->sub_services = $booking_sub_Services; 
                           }else{
                               $bookings[$key]->sub_services = []; 
                           }
                        endforeach;
                    $response=array("status"=>1,"message"=>"Bookings found.", "data" => $bookings);
               }else{
                    $response=array("status"=>0,"message"=>"No bookings found on selected date!", "data" => NULL);   
               }
           }else{
               $response=array("status"=>0,"message"=>"End date must be greater than start date!", "data" => NULL);   
           }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function viewEmpBookingDetails(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $booking_id = $this->request->getVar('id'); 
            $booking_discount_amount = $this->request->getVar('discount_amount');
            
                $get_booking_details = $this->AddBookingModel->getWhere(['id'=>$booking_id,'emp_id'=>$userData['emp_id']])->getRowArray();
                if(!empty($get_booking_details)){
                          $business_id = $get_booking_details['business_id'];
                          $booking_id = $get_booking_details['id'];
                          $emp_id = $get_booking_details['emp_id'];
                          $user_id = $get_booking_details['user_id'];
                          
                          $get_user_dtl = $this->UserModel->get_user_dtl_bus($user_id);
                          if(!empty($get_user_dtl)){
                               $get_booking_details['user'] = $get_user_dtl;
                          }else{
                               $get_booking_details['user'] = []; 
                          }
                           
                           $booking_sub_Services = $this->BookingsServicesModel->get_open_booking_sub_services($booking_id,$user_id);
                           if(!empty($booking_sub_Services) && !empty($emp_id)){
                               $get_booking_details['sub_services'] = $booking_sub_Services; 
                           }else{
                               $get_booking_details['sub_services'] = []; 
                           }
                           
                           if(!empty($business_id)){
                               $get_booking_rating = $this->RateReviewBusinessEmployeeModel->get_booking_rating_by_user_to_bus($booking_id,$user_id,$business_id);
                               if(!empty($get_booking_rating)){
                                    $get_booking_details['business_rating'] = $get_booking_rating['rating'];
                                    $get_booking_details['business_review'] = $get_booking_rating['review'];
                               }else{
                                    $get_booking_details['business_rating'] = "0";
                                    $get_booking_details['business_review'] = "0";
                               }
                           }
                           
                           if(!empty($emp_id)){
                               $get_booking_rating = $this->RateReviewBusinessEmployeeModel->get_booking_rating_by_user_to_emp($booking_id,$user_id,$emp_id);
                               if(!empty($get_booking_rating)){
                                    $get_booking_details['emp_rating'] = $get_booking_rating['rating'];
                                    $get_booking_details['emp_review'] = $get_booking_rating['review'];
                               }else{
                                    $get_booking_details['emp_rating'] = "0";
                                    $get_booking_details['emp_review'] = "0";
                               }
                           }
                           
                           $get_applied_discount_code = $this->AddBookingModel->get_booking_applied_discount_code($user_id,$booking_id);
                            if(!empty($booking_discount_amount)){
                               $promo_code_percentage = implode(',', $get_applied_discount_code);
                               $get_booking_details['promo_code_applied_percentage'] = $promo_code_percentage;
                            }else{
                               $get_booking_details['promo_code_applied_percentage'] = "";
                            }
                            
                            $get_booking_payment_details = $this->AddBookingModel->get_booking_payment_details($user_id,$booking_id);
                            if(!empty($get_booking_payment_details)){
                               $get_booking_details['payment_details'] = $get_booking_payment_details;
                            }else{
                               $default = array (
                                    "amount" => "",
                                    "payment_method_type" => "",
                                    "payment_status" => ""
                                );
                                $get_booking_details['payment_details'] = $default;
                            }
                    $response = array("status"=>1, "message"=>"Booking details found.", "data" => $get_booking_details);
                }else{
                    $response = array("status"=>0, "message"=>"Booking details not found!", "data" => NULL);
                }
        }else{
            $response = array("status"=>0, "message"=>"User not found", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function addEmployeeBooking(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $emp_id = $userData['emp_id'];
		    $client_id = $this->request->getVar('client_id');
		    $booking_date = $this->request->getVar('booking_date');
		    $booking_timestamp = strtotime($booking_date);
		    $booking_time = $this->request->getVar('booking_time');
    		$time = time(); 
    		$current_date = date("Y-m-d",$time);
    		$status = '0'; //0=Open
    		$created_at	= date('Y-m-d H:i:s');
    		$type = "2";
    		
    		$data = [
    			'emp_id'	    => $emp_id,
    			'booking_date'	=> $booking_date,
    			'booking_time'	=> $booking_time,
    			'created_at'	=> $created_at,
    			'status'        => $status,
    			'user_id'     => $client_id,
    			'type'          => $type,
    			'business_id'   => $userData['business_id'],
    			'payment_type'  => '0' //In-Shop
    		];
    		
    		if($booking_timestamp >= strtotime($current_date)){
		     $result = $this->AddBookingModel->insert($data);
		     $last_inserted_id = $this->AddBookingModel->insertID();
    		    if(!empty($last_inserted_id)) {
    		        $sub_service_id = array();
    		        $sub_service_id = (explode(",",$this->request->getVar('sub_service_id')));
    		        foreach ($sub_service_id as $row) {  
    		            $get_sub_nam = $this->SubServiceModel->get_sub_service_name($row);
                            $sub_services['sub_services'] = $row;
            		        $data = [
                    		    'sub_service_id' => $sub_services,
                    			'booking_id'	 => $last_inserted_id,
                    			'user_id'        => $client_id,
                    			'sub_service_name' => $get_sub_nam['sub_service_name'],
                    		];
            		        $upresult = $this->BookingsServicesModel->insert($data);
                    }
                    $response=array("status"=>1,"message"=>"Booking added successfully.", "data" => $upresult);
                }else {
                    $response=array("status"=>0,"message"=>"Booking not added, please try again!");
                }
    		}
    		else{
    		    $response=array("status"=>0,"message"=>"Booking date must be greater than or equal to current date!", "data" => NULL);
    		}
        }else{
            $response = array("status"=>0, "message"=>"User not found", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function cancelEmployeeBooking(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $emp_id= $userData['emp_id'];
            $booking_id = $this->request->getVar('id');
            $booking_reason = $this->request->getVar('write_cancel_reason');
            $current_date = date("Y-m-d");
        
            $get_booking_date = $this->AddBookingModel->getWhere(['id'=>$booking_id])->getRowArray();
            if($get_booking_date['booking_date'] < $current_date){
                $response=array("status"=>0,"message"=>"You cannot cancel bookings on past days!", "data" => NULL); 
            }else{
                $data = ['status' => '2'];
                $result = $this->AddBookingModel->update($booking_id, $data);
                
                if(!empty($result)){
                    $insert = ['booking_id'=>$booking_id,'cancel_reason_text'=>$booking_reason];
                    $cancel_reason = $this->CancelBookingsModel->insert($insert);
    		        $response=array("status"=>1,"message"=>"Booking cancelled successfully.", "data" => $cancel_reason);
                }else{
                    $response=array("status"=>0,"message"=>"Booking not cancelled, please try again!", "data" => NULL); 
                }
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function modifyEmployeeBooking(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $booking_id = $this->request->getVar('id');
            $booking_date = $this->request->getVar('booking_date');
            $booking_timestamp = strtotime($booking_date);
            $booking_time = $this->request->getVar('booking_time');
            $time = time(); 
            $current_date = date("Y-m-d",$time);
                
            $data = [
                'booking_date'  => $booking_date,
                'booking_time'  => $booking_time,
            ];
            
            if($booking_timestamp >= strtotime($current_date)){
                $result = $this->AddBookingModel->update($booking_id,$data);
                $sub_service_id = $this->request->getVar('sub_service_id');
                $services = explode(',', $sub_service_id);
                
                $get_booking_id = $this->AddBookingModel->getWhere(['id' => $booking_id])->getRowArray();
                if(!empty($get_booking_id)) {
                    $this->BookingsServicesModel->where(['booking_id' => $get_booking_id['id']])->delete();
                    foreach($services as $serve) :
                        $get_sub_nam = $this->SubServiceModel->get_sub_service_name($serve);
                            $data = array(
                                'sub_service_id' => $serve,
                                'booking_id'     => $get_booking_id['id'],
                                'user_id'     => $get_booking_id['user_id'],
                                'sub_service_name' => $get_sub_nam['sub_service_name'],
                            );
                            $result = $this->BookingsServicesModel->save($data);
                    endforeach;
                    $response=array("status"=>1,"message"=>"Booking modified successfully.", "data" => $result);
                }
                else {
                    $response=array("status"=>0,"message"=>"Booking not modified, please try again!","data" =>NULL);
                }
            }
            else{
                $response=array("status"=>0,"message"=>"Booking date must be greater than or equal to current date!", "data" => NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function rescheduleEmployeeBooking(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $emp_id= $userData['emp_id'];
            $booking_id = $this->request->getVar('id');
            $booking_date = $this->request->getVar('booking_date');
            $booking_timestamp = strtotime($booking_date);
            $booking_time = $this->request->getVar('booking_time');
            $time = time(); 
            $current_date = date("Y-m-d",$time);
             
            $data = [
                'booking_date'  => $booking_date,
                'booking_time'  => $booking_time,
            ];
            
            if($booking_timestamp >= strtotime($current_date)){
                $result = $this->AddBookingModel->update($booking_id,$data);
                $get_updated_data = $this->AddBookingModel->getWhere(['id'=>$booking_id])->getRowArray();
                if(!empty($result)){
                    $response=array("status"=>1,"message"=>"Booking rescheduled successfully.", "data" => $get_updated_data);
                }else{
                     $response=array("status"=>0,"message"=>"Booking not rescheduled, please try again!","data" =>NULL);
                }
            }
            else{
                $response=array("status"=>0,"message"=>"Booking date must be greater than or equal to current date!", "data" => NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function getModifyRescheduleEmployeeBookingDetails(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $booking_id = $this->request->getVar('id');
            $type = $this->request->getVar('type'); //0=Reschedule,1=Modify
            
            $get_booking_id_dtls = $this->AddBookingModel->getWhere(['id' => $booking_id])->getRowArray();
            if(!empty($get_booking_id_dtls)){
                if($type == "1"){
                    $business_id = $get_booking_id_dtls['business_id'];
                    $booking_id = $get_booking_id_dtls['id'];
                    $emp_id = $get_booking_id_dtls['emp_id'];
                    $user_id = $get_booking_id_dtls['user_id'];
                   
                    $booking_sub_Services = $this->BookingsServicesModel->get_open_booking_sub_services($booking_id,$user_id);
                    if(!empty($booking_sub_Services) && !empty($business_id)){
                       $get_booking_id_dtls['sub_services'] = $booking_sub_Services; 
                    }else{
                       $get_booking_id_dtls['sub_services'] = []; 
                    }
                    $response = array("status"=>1, "message"=>"Modify booking details found.", "data" => $get_booking_id_dtls);
                }else{
                    $business_id = $get_booking_id_dtls['business_id'];
                    $booking_id = $get_booking_id_dtls['id'];
                    $emp_id = $get_booking_id_dtls['emp_id'];
                    $user_id = $get_booking_id_dtls['user_id'];
                       
                    $get_user_dtl = $this->UserModel->get_user_dtl_bus($user_id);
                    if(!empty($get_user_dtl)){
                        $get_booking_id_dtls['user'] = $get_user_dtl;
                    }else{
                        $get_booking_id_dtls['user'] = []; 
                    }
                    $response = array("status"=>1, "message"=>"Reschedule booking details found.", "data" => $get_booking_id_dtls);
                }
            }else{
                $response = array("status"=>0, "message"=>"Booking details not found!", "data" => NULL);
            }
        }else{
           $response=array("status"=>0,"message"=>"User not found!", "data" => NULL); 
        }
        return $this->respond($response);
    }
    
    public function searchEmpBookings(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $emp_id = $userData['emp_id'];
            $search = $this->request->getVar('search');
            
            if(!empty($search)){
                $bookings = $this->AddBookingModel->get_searched_bookings_emp($search,$emp_id);
                if(!empty($bookings)){
                     foreach($bookings as $key=>$service) :
                           $booking_id = $service->id;
                           $user_id = $service->user_id;
                           $emp_id = $service->emp_id;
                           
                           $get_booking_user_name = $this->UserModel->get_user_dtl_bus($user_id);
                           if(!empty($get_booking_user_name) && !empty($user_id)){
                               $bookings[$key]->user = $get_booking_user_name;
                           }else{
                               $bookings[$key]->user = []; 
                           }
                           
                           $get_booking_payment_details = $this->AddBookingModel->get_booking_payment_total_amount($user_id,$booking_id);
                            if(!empty($get_booking_payment_details)){
                               $convert = implode(',',$get_booking_payment_details);
                               $bookings[$key]->amount = $convert;
                            }else{
                               $bookings[$key]->amount = "";
                            }
                           
                           $booking_sub_Services = $this->BookingsServicesModel->get_booking_sub_services($booking_id,$user_id);
                           if(!empty($booking_sub_Services) && !empty($emp_id)){
                               $bookings[$key]->sub_services = $booking_sub_Services; 
                           }else{
                               $bookings[$key]->sub_services = []; 
                           }
                     endforeach;
                     $response = array("status"=>1, "message"=>"Bookings found.", "data" => $bookings);
                }else{
                     $response = array("status"=>0, "message"=>"No bookings found!", "data" => NULL);
                }
            }else{
                $response = array("status"=>0, "message"=>"Please enter user or service name to view bookings!", "data" => NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function searchEmployeeClients(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $emp_id = $userData['emp_id'];
            $search = $this->request->getVar('search');
            
            $clients = $this->UserModel->get_emp_search_clients($search,$emp_id);
            if(!empty($clients)){
                $response = array("status"=>1, "message"=>"Client found.", "data" => $clients);
            }else{
                $response = array("status"=>0, "message"=>"No Client found!", "data" => NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function manageEmpWorkingHours(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $timings = $this->request->getVar('timings');
            $created_at	= date('Y-m-d H:i:s');
            
            $listBreaks = $this->EmployeeHoursModel->getWhere(["emp_id" =>$userData['emp_id']])->getRowArray();
            $id = $listBreaks['id'];
            if (!empty($listBreaks)) { //edit
                 $data = [
                            "timings"     => $timings,
                         ];
                        
                if(!empty($data)){
                    $update = $this->EmployeeHoursModel->update($id,$data);
                    $response = array("status"=>1, "message"=>"Employee working hours updated successfully.", "data" => $update); 
                }else{
                    $response = array("status"=>0, "message"=>"Business working hours not updated, please try again!", "data" => NULL); 
                }
            } 
            else { //add
                $data = [
                            "emp_id" => $userData['emp_id'],
                            "timings"     => $timings,
                            "created_at"  => $created_at,
                        ];
                        
                if(!empty($data)){
                    $insert = $this->EmployeeHoursModel->insert($data);
                    $response = array("status"=>1, "message"=>"Employee working hours added successfully.", "data" => $insert); 
                }else{
                    $response = array("status"=>0, "message"=>"Employee working hours not added, please try again!", "data" => NULL); 
                }
            }
        }else{
            
        }
        return $this->respond($response);
    }
    
    public function viewEmpWorkingHours(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
    
        if(!empty($userData)) {
            $workData = $this->EmployeeHoursModel->getWhere(["emp_id" =>$userData['emp_id']])->getRowArray();
            
            if(!empty($workData)){
                $workData['timings'] = json_decode($workData['timings']);
                $response = array("status"=>1, "message"=>"Employee Working Hours found.", "data" => $workData);
            }else{
                $response = array("status"=>0, "message"=>"Working Hours not found", "data" => NULL);
            }
        }else{
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        }
        return $this->respond($response); 
    }
    
    //Notifications settings start
    public function sendNotification(){
        $url = "https://fcm.googleapis.com/fcm/send";
        
        //Notification types : 0=Bookings,1=Admin,2=Rating&Reviews,3=SubscriptionPlan,4=Advertisements,5=Business,6=UpcomingAppointments
        if($type == 0) { 
            $title = $data['notification_title'];
            $msg = $data['notification_msg'];
        
            $notification = array("title" => $title, "body" => $msg, "userId" => $data['senderId'], 
            "message" => $msg, "type" => $type, "click_action" => "home", 'priority'=>'high', 'sound' => "default", 
            "badge" => "1", "content-available" => true); 
        
            $newData = array('messageType'=> '0', 'notificationTypeId'=> $type, 'contactId'=> '0', 'attachmentLink' => '0', 
            'text'=> $title, 'notificationType' => 'Message', 'title' => $title, 'message' => $msg);
        }else{
            
        } 
        
        $builder = $this->db->table("user_tbl");
        $builder->select('device_id, device_type, device_token');
        $builder->where('id', $data['receiverId']);
        $query = $builder->get();
        $row = $query->getRowArray();
        
        if($row['is_notification'] == "1"){
            if(($row['device_type'] == "android") || ($row['device_type'] == "web")){
                $arrayToSend = array('to' => $row['device_token'], 'data' => $newData);
            }else{
                $arrayToSend = array('to' => $row['device_token'], 'notification' => $notification, 'data' => $newData);
            } 
        }else{}
        
         
        
        date_default_timezone_set('UTC');
        $date = date('Y-m-d H:i:s');
        
        $headers = array (
            'Authorization: key=AAAARJ-Jzb4:APA91bGvlD8vOqNn84Zy4AKrymfvnbDPeManS2UyrgQmOTYWVGIXZbzGyIPlV2ySf7ErTBVZHdRbDSHMUq1vlvuGeWglLrkK-ZFNz-UoZd4tHFd_3xgmSRfoYqoybofDhAQDJBWf79bP',
            'Content-Type: application/json'
        );
        
        $ch = curl_init ();
        curl_setopt ( $ch, CURLOPT_URL, $url );
        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_HTTPHEADER, $headers );
        curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, json_encode ( $arrayToSend ) );
        
        $result = curl_exec ( $ch );
        $resultsArray=json_decode($result);
        $success=$resultsArray->success;
        
        curl_close ( $ch );
        
        if($success == 1) {
            $result = $this->NotificationModel->save($data);
            return $result; 
        }     
    }
    
    public function userNotificationSettings(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $type = $this->request->getVar('type'); //0=Off,1=On
            
            $data = [
                'is_notification' => $type
            ];
            $update = $this->UserModel->update($userData['id'],$data);
            
            if(!empty($update)){
                $updated_data = $this->UserModel->getWhere(['id'=>$userData['id']])->getRowArray();
                if($updated_data['is_notification'] == "1"){
                    $response = array("status"=>1, "message"=>"Notifications on.", "data" => NULL);
                }else{
                    $response = array("status"=>1, "message"=>"Notifications off.", "data" => NULL);
                }
            }else{
                $response=array("status"=>0,"message"=>"Notification settings not changed!", "data" => NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function notificationSettings(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
        if(!empty($userData)){
            $bookings = $this->request->getVar('bookings'); //0=Off,1=On
            $admin = $this->request->getVar('admin'); 
            $rating_reviews = $this->request->getVar('rating_reviews'); 
            $subscription_plan = $this->request->getVar('subscription_plan'); 
            $advertisements = $this->request->getVar('advertisements'); 
            
            $check = $this->NotificationSettingsModel->getWhere(['user_id'=>$userData['id']])->getRowArray();
            if(!empty($check)){
                $data = [
                    'bookings' => $bookings,
                    'admin' => $admin,
                    'rating_reviews' => $rating_reviews,
                    'subscription_plan' => $subscription_plan,
                    'advertisements' => $advertisements,
                ];
                $this->NotificationSettingsModel->update($check['id'],$data);
                $response = array("status"=>1, "message"=>"Notifications settings changed.", "data" => NULL);
            }else{
                $data = [
                    'user_id' => $userData['id'],
                    'user_type'  => '2',
                    'bookings' => $bookings,
                    'admin' => $admin,
                    'rating_reviews' => $rating_reviews,
                    'subscription_plan' => $subscription_plan,
                    'advertisements' => $advertisements,
                ];
                $this->NotificationSettingsModel->insert($data);
                $response = array("status"=>1, "message"=>"Notifications settings changed.", "data" => NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function getNotifications(){
        $userId = $this->decodeToken();
        $userData = $this->UserModel->get_single_userdata($userId);
        
		if(!empty($userData)){
		    $nots = $this->NotificationSettingsModel->getWhere(['user_id'=>$userData['id']])->getRowArray();
		    if(!empty($nots)){
		        $response = array("status"=>1, "message"=>"Notifications settings found.", "data" => $nots);
		    }else{
		        $response = array("status"=>0, "message"=>"Notifications settings not found!", "data" => NULL);
		    }
		}else{
		    $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
		}
		return $this->respond($response);
    }
    
    public function empNotificationSettings(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
    
        if(!empty($userData)){
            $bookings = $this->request->getVar('bookings'); //0=Off,1=On
            $admin = $this->request->getVar('admin'); 
            $rating_reviews = $this->request->getVar('rating_reviews'); 
            $business = $this->request->getVar('business'); 
            $upcoming_appointments = $this->request->getVar('upcoming_appointments'); 
            
            $check = $this->NotificationSettingsModel->getWhere(['user_id'=>$userData['emp_id']])->getRowArray();
            if(!empty($check)){
                $data = [
                    'bookings' => $bookings,
                    'admin' => $admin,
                    'rating_reviews' => $rating_reviews,
                    'business' => $business,
                    'upcoming_appointments' => $upcoming_appointments,
                ];
                $this->NotificationSettingsModel->update($check['id'],$data);
                $response = array("status"=>1, "message"=>"Notifications settings changed.", "data" => NULL);
            }else{
                $data = [
                    'user_id' => $userData['emp_id'],
                    'user_type'  => '3',
                    'bookings' => $bookings,
                    'admin' => $admin,
                    'rating_reviews' => $rating_reviews,
                    'business' => $business,
                    'upcoming_appointments' => $upcoming_appointments,
                ];
                $this->NotificationSettingsModel->insert($data);
                $response = array("status"=>1, "message"=>"Notifications settings changed.", "data" => NULL);
            }
        }else{
            $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
        }
        return $this->respond($response);
    }
    
    public function getEmpNotifications(){
        $userId = $this->empdecodeToken();
        $userData = $this->EmployeeModel->get_single_userdata($userId);
        
		if(!empty($userData)){
		    $nots = $this->NotificationSettingsModel->getWhere(['user_id'=>$userData['emp_id']])->getRowArray();
		    if(!empty($nots)){
		        $response = array("status"=>1, "message"=>"Notifications settings found.", "data" => $nots);
		    }else{
		        $response = array("status"=>0, "message"=>"Notifications settings not found!", "data" => NULL);
		    }
		}else{
		    $response=array("status"=>0,"message"=>"User not found!", "data" => NULL);
		}
		return $this->respond($response);
    }
    //Notifications settings end
    
}
