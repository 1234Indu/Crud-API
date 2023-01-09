<?php

#--------------------------------------------------------------------
# JWT
#--------------------------------------------------------------------
JWT_SECRET = 'Molten7534)($%^951*?/!*^!389?><~`+=' ==(Any custom number,alphabets,symbols etc.)

//Set key in .env file
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

//Use JWT towen in functions
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

?>