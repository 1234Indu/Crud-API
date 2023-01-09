<?php

namespace App\Controllers\API;
use App\Controllers\BaseController;
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
//Testing Model CrudModel.
use App\Models\CrudModel;

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;
use CodeIgniter\I18n\Time;
use Twilio\Rest\Client;
use CodeIgniter\Files\File;

class Home extends BaseController
{
    use ResponseTrait;
    private $db;

    public function __construct()
    {
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
        //Testing Model CrudModel.
        $this->CrudModel = new CrudModel();
    }

    private function getjwtKey()
    {
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

    public function commonDecodeToken()
    {
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

    public function empcommonDecodeToken()
    {
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

    public function decodeToken()
    {
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
    
    public function empdecodeToken()
    {
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
            //print_r($response, 401);
            http_response_code(401);
            print_r(json_encode($response, JSON_PRETTY_PRINT));
            exit();
        }    
    }

    private function getsendgridKey()
    {
        return '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';
    }

    public function sendGridEmail($to_email, $type, $emailData) {
        require 'vendor/autoload.php';

        $sendgridKey = $this->getsendgridKey();
        
        $grid = new \SendGrid\Mail\Mail();

        $from_email = "dinesh@parastechnologies.com";
        $receiverEmail = "parasdinesh8610@gmail.com";
      
        if( ($type == 1) || ($type == 4) || ($type == 5) ) {
            if($emailData['usertype'] == 1) {
                if($type == 1) {
                    $grid->setSubject("Moten E-mail Verification");
                } else if($type == 5) {
                    $grid->setSubject("Moten Forgot Verification");
                } else {
                    $grid->setSubject("Moten E-mail Verification");
                }    
            } else {
                if($type == 1) {
                    $grid->setSubject("Moten E-mail Verification");
                } else if($type == 5) {
                    $grid->setSubject("Moten Forgot Verification");
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

    public function registerVerify() {
        $userEmail = $this->request->getVar('email');
        $userType = $this->request->getVar('type');

        $checkEmail = $this->UserModel->checkemailTypeExist($userEmail, $userType);

        if($checkEmail > 0) {
            $response=array("status"=>0,"message"=>"E-mail already exist");
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
                        $response=array("status"=>1,"message"=>"Otp successfully sent on your e-mail");
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
                    $response=array("status"=>1,"message"=>"Otp successfully sent on your e-mail");
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
            $response = array("status"=>0, "message"=>"Otp Invalid");
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
                        
                        
                        $response = array("status"=>1, "message"=>"Registeration successfully", "data" => $updateduserData, "token" => $userToken);
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
            $response = array("status"=>0, "message"=>"E-mail already registered.");
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
            $userPhn = $this->request->getVar('mobile');
            
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
                                'user_img' => $name
                            ]; 
                        } else {
                            $data = [
                                'first_name' => $userFirst,
                                'last_name' => $userLast,
                                'user_img' => $name,
                                'country_code' => $userCc,
                                'mobile' => $userPhn
                            ];   
                        }    
                    } else {
                        $data = [
                            'first_name' => $userFirst,
                            'last_name' => $userLast,
                            'user_img' => $name
                        ]; 
                    } 
                        $result = $this->UserModel->update($userData['id'], $data);
                } else {
                    $response=array("status"=>0,"message"=>"Please upload jpg|png|jpeg|gif image format.");
                }    
            } else {

                if( (!empty($userCc)) && (!empty($userPhn)) ) {
                    if( ($userCc == $userData['country_code']) && ($userPhn == $userData['mobile'])) {
                        $data = [
                            'first_name' => $userFirst,
                            'last_name' => $userLast
                        ]; 
                    } else {
                        $data = [
                            'first_name' => $userFirst,
                            'last_name' => $userLast,
                            'country_code' => $userCc,
                            'mobile' => $userPhn
                        ];   
                    }    
                } else {
                    $data = [
                        'first_name' => $userFirst,
                        'last_name' => $userLast
                    ]; 
                } 
                
                $result = $this->UserModel->update($userData['id'], $data);
            }    
        }  else {
            $response = array("status"=>0, "message"=>"User doesn't exist", "data" => NULL);
        } 
            return $this->respond($response); 
    }

    public function privacyPolicy() {       
        $pageData = $this->PageModel->getWhere(["slug" => "privacy-policy"])->getRowArray();

        if(!empty($pageData)) {
            $response = array("status"=>1, "message"=>"content available", "data" => $pageData['page_content']);
        } else {
            $response = array("status"=>0, "message"=>"content not available", "data" => NULL);
        } 
            return $this->respond($response);    
    }

    public function termCondition() {       
        $pageData = $this->PageModel->getWhere(["slug" => "term-condition"])->getRowArray();

        if(!empty($pageData)) {
            $response = array("status"=>1, "message"=>"content available", "data" => $pageData['page_content']);
        } else {
            $response = array("status"=>0, "message"=>"content not available", "data" => NULL);
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
                $response = array("status"=>1, "message"=>"Your message has been sent successfully. Thank you.");
            } else {
                $response = array("status"=>0, "message"=>"not posted");
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
                $response=array("status"=>0,"message"=>"Old password is incorrect.");
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
            $userStatus = $this->request->getVar('status');
            //0=Off, 1=On
            $data = array('is_notification' => $userStatus);
            $this->UserModel->update($userData['id'], $data);
            $updateduserData = $this->UserModel->get_single_userdata($userData['id']);

            if($userStatus == 0) {
                $response = array("status"=>1, "message"=>"Notification status Off", "data" => $updateduserData);
            } else {
                $response = array("status"=>1, "message"=>"Notification status On", "data" => $updateduserData);
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

    public function userHome() {
        $userId = $this->decodeToken();
        
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            $response = array("status"=>0, "message"=>"User Home screen", "data" => $userData);
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
                $response=array("status"=>1,"message"=>"Otp successfully sent on your e-mail");
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
                
                $data = array(
                            'business_name' => $userBusiness,
                            'business_address_1' => $userStreet1,
                            'business_address_2' => $userStreet2,
                            'business_city' => $userCity,
                            'business_province' => $userProv,
                            'business_postal_code' => $userPostal,
                            'business_country_code' => $userCcode,
                            'business_phone' => $userphn,
                            'business_id' => $userId
                        );
                $this->BusinessDetailModel->save($data);
                
                $udata = array('is_complete' => '1', 'is_step' => '2');
                $this->UserModel->update($userData['id'], $udata);
                $updateduserData = $this->UserModel->get_single_userdata($userId);
            
                $response = array("status"=>1, "message"=>"Business details added successfully", "data" => $updateduserData); 
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
        }  else {
            $response = array("status"=>0, "message"=>"plans not found", "data" => []);
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
    
    public function getbusinessHours() {
        $userId = $this->decodeToken();
        
        $userData = $this->UserModel->get_single_userdata($userId);

        if(!empty($userData)) {
            if($userData['user_type'] == 2) {
                $workData = $this->BusinessWorkingHourModel->get_business_working_hours($userId);
                $columns = array_column($workData, 'id');
                array_multisort($columns, SORT_ASC, $workData);
                
                if(!empty($workData)) {
                    $response = array("status"=>1, "message"=>"Working Hours found.", "data" => $workData);
                } else {
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

                    $udata = array('is_step' => '3');
                    $this->UserModel->update($userData['id'], $udata);

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
                $businessCatData = $this->AssignedBusinessCategoryModel->getWhere(["business_id" => $userId])->getRowArray();

                $services = $this->ServiceCategoryModel->getWhere(["business_industry" => $businessCatData['bussiness_category_id']])->getResultArray();

                if(!empty($services)) {
                    $columns = array_column($services, 'service_name');
                    array_multisort($columns, SORT_ASC, $services);
                    $response = array("status"=>1, "message"=>"Services found", "data" => $services); 
                } else {
                    $response = array("status"=>0, "message"=>"Services not found", "data" => []); 
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
                
                foreach($services as $serve) :
                    $data = array(
                        'business_id' => $userId,
                        'business_service_id' => $serve
                    );

                    $this->AssignedBusinessServiceModel->save($data);
                endforeach;

                $udata = array('is_step' => '4');
                $this->UserModel->update($userData['id'], $udata);

                $updatedUserData = $this->UserModel->get_single_userdata($userId);

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

                $udata = array('is_step' => '5');
                $this->UserModel->update($userData['id'], $udata);

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
                $file = $this->request->getVar('empimg');
                $userFirst = $this->request->getVar('firstname');
                $userLast = $this->request->getVar('lastname');
                $userEmail = $this->request->getVar('email');
                $userGender = $this->request->getVar('gender');
                $userTitle = $this->request->getVar('title');
                $userDesc = $this->request->getVar('desc');
                $userPwd = "WelcomeMoten";

                if( ($file != '') && (isset($file)) ) {
                    $ext = $file->getClientExtension();
                        
                    if( ($ext == "png") || ($ext == "jpg") || ($ext == "gif") || ($ext == "jpeg") ) {
                        $name = $file->getRandomName();

                        $file->move('public/employeeImg', $name);

                        $data = array('emp_img' => $userImg, 'emp_first_name' => $userFirst, 'emp_last_name' => $userLast, 'emp_email' => $userEmail, 'emp_password' => $userPwd, 'emp_gender' => $userGender, 'emp_title' => $userTitle, 'emp_desc' => $userDesc, 'business_id' => $userId);

                    } else {
                        $data = array();
                        $response=array("status"=>0,"message"=>"Please upload jpg|png|jpeg|gif image format.");
                    }      
                } else {
                    $data = array('emp_first_name' => $userFirst, 'emp_last_name' => $userLast, 'emp_email' => $userEmail, 'emp_password' => $userPwd, 'emp_gender' => $userGender, 'emp_title' => $userTitle, 'emp_desc' => $userDesc, 'business_id' => $userId);
                }    
                    $this->EmployeeModel->save($data);

                    $udata = array('is_step' => '6');
                    $this->UserModel->update($userData['id'], $udata);

                    $updatedUserData = $this->UserModel->get_single_userdata($userId);

                    $response = array("status"=>1, "message"=>"Employee added successfully", "data" => $updatedUserData);
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
                $services = $this->AssignedBusinessServiceModel->getWhere(["business_id" => $userId])->getResultArray();

                if(!empty($services)) {
                    foreach($services as $serve) :
                        $businessService = $serve['business_service_id']; 
                        $allService[] = $this->ServiceCategoryModel->getWhere(["service_id" => $businessService])->getRowArray();
                    endforeach;
              
                    foreach($allService as $key=>$service) :
                       $serviceID = $service['service_id'];
                       $allService[$key]['subservices'] = $this->SubServiceModel->getWhere(["service_id" => $serviceID, "business_id" => $userId])->getResultArray();
                    endforeach;
                    $response = array("status"=>1, "message"=>"Services found", "data" => $allService); 
                }  else {
                    $response = array("status"=>0, "message"=>"Services not found", "data" => NULL); 
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
        
        if(!empty($userData)) {
            $pwd_verify = password_verify($userPwd, $userData['emp_password']);

            if(!$pwd_verify) {
                $response=array("status"=>0,"message"=>"The password you have entered is incorrect. Please try again.");
            }  else { 
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
        } else {
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
                $response = array("status"=>1, "message"=>"Your message has been sent successfully. Thank you.");
            } else {
                $response = array("status"=>0, "message"=>"not posted");
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
    
    //Testing functions start for CRUD opeartion.
    public function insertdata() {
        $name	= $this->request->getVar('name');
		$email	= $this->request->getVar('email');
		$data = [
			'name'	=> $name,
			'email'	=> $email,
		];
		
		$val = $this->validate([
            'name' => 'required',
            'email' => 'required',
        ]);
        
        if (!$val){
            echo \Config\Services::validation()->listErrors();
        }else{
            $checkEmail = $this->CrudModel->emailExist($email);
            if($checkEmail == 0){
    		    $result = $this->CrudModel->insertdatafun($data);
    		    if($result == 1) {
                    $response=array("status"=>1,"message"=>"Data inserted successfully.");
                }else {
                    $response=array("status"=>0,"message"=>"Data not inserted, please try again!");
                }
            }else{
                 $response=array("status"=>0,"message"=>"Email already exists, please enter a different email address!");
            }
        }
		return $this->respond($response);   
    }
    
    public function viewdata(){
         $data = $this->CrudModel->viewdatafun();
         if(!empty($data)) {
                $response=array("status"=>1,"message"=>"Data fetched successfully.","data" => $data);
         }else {
                $response=array("status"=>0,"message"=>"Data not fetched, please try again!", "data" => NULL);
         }
		 return $this->respond($response); 
    }
    
    public function updatedata(){
        $id = $this->request->getVar('id');
		$data = [
			'name'		=> $this->request->getVar('name'),
			'email'			=>  $this->request->getVar('email'),
		];
		
		$val = $this->validate([
            'name' => 'required',
            'email' => 'required',
        ]);
        
        if (!$val){
            echo \Config\Services::validation()->listErrors();
        }else{
            $email = $this->request->getVar('email');
            $checkEmail = $this->CrudModel->emailExist($email);
            if($checkEmail == 0){
    		    $result = $this->CrudModel->update($id,$data);
        		$userID = $this->CrudModel->where('id', $id)->first();
        		
                $userToken = $this->encodeTokenCrud($userID);
        		if(!empty($userToken)) {
        		        $response = array("status"=>1, "message"=>"Data updated successfully.", "data" => $userID, "token" => $userToken);
                }else {
                        $response=array("status"=>0,"message"=>"Data not updated, please try again!", "data" => NULL);
                }
            }else{
                 $response=array("status"=>0,"message"=>"Email already exists, please enter a different email address!");
            }
        }
		return $this->respond($response);   
    }
    
    public function deletedata(){
        $id = $this->request->getVar('id');
        $result = $this->CrudModel->delete($id);
        $userID = $this->CrudModel->where('id', $id)->first();
		if(empty($userID)) {
                $response=array("status"=>1,"message"=>"User deleted successfully.");
        }else {
                $response=array("status"=>0,"message"=>"User not deleted, please try again!");
        }
		return $this->respond($response);   
    }
    
    public function getuser(){
        $userId = $this->request->getVar('id');
        $userData = $this->CrudModel->getuserdata($userId);
        
        if(!empty($userData)) {
            $response = array("status"=>1, "message"=>"User found successfully.", "data" => $userData);
        } else {
            $response = array("status"=>0, "message"=>"User not found.", "data" => NULL);
        }  
        return $this->respond($response);
    }
    
    public function joindata(){
        $result = $this->CrudModel->joindatafun();
        if(!empty($result)) {
                $response=array("status"=>1,"message"=>"Data joined successfully.","data" => $result);
        }else {
                $response=array("status"=>0,"message"=>"Data not joined, please try again!", "data" => NULL);
        }
		return $this->respond($response);
    }
    
    //JWT Code start
    public function encodeTokenCrud($token) {
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
            "id" => $token['id']
        );
       
        $token = JWT::encode($payload, $key, 'HS256');

        return $token;
    }
    
    public function commonDecodeTokenCrud()
    {
            $key = $this->getjwtKey();
            $authHeader = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
    
            if(!empty($authHeader)) {
                $arr = explode(" ", $authHeader);
    
                $token=$arr[1];
    
                try {
                    $decodedToken = JWT::decode($token, new Key($key, 'HS256'));
                    $userID = $decodedToken->id;
                    return ["userID" => $userID];
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
    
    public function decodeTokenCrud()
    {
            $decode = $this->commonDecodeTokenCrud();
            $userData = $this->CrudModel->getWhere(["id" => $decode['userID']])->getRowArray();
      
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
    
    //JWT code end
    
    //Testing functions end for CRUD opeartion.
}
