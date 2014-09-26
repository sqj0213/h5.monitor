<?php
class AuthController extends BaseController {
    private $authObj = NULL;
    public function __construct()
    {   
        $this->authObj = new MyAuth();
    }
    public function auth()
    {
        $userKey = Input::get( 'userKey');

        $this->authObj->auth( $userKey );
        $retData = $this->authObj->getRetData();
        return View::make('api.api')->with( 'retData', $retData );
    }

    public function checkApiInvalid()
    {
//        $this->authObj->apiCheckInvalid(Request::get('userName'), Request::header('token'), Request::header('deviceID'));
        
        if ( $this->authObj->apiCheckInvalid(Request::get('userName'), Request::get('token'), Request::get('deviceID')) )
            header("X-Accel-Redirect: /api/getuserinfo?userName=".Request::get('userName'));
        else
        {
            $retData = $this->authObj->getRetData();
            return View::make('api.api')->with( 'retData', $retData );
        }
    }


/**
 * functionName
 *
 * @access public
 * @return string $mixed
 */
    public function test() {
        $user = 'jigui';
        $passwd = 'Hjg_13562';
        $timestamp = 1411639029;
        $dev_id = 1411639029;

        $input = $user.','.$passwd.','.$timestamp.','.$dev_id;
        echo "plainText:" . $input."<br/>";


        $Crypt3Des = App::make('Crypt3Des');
        $encrypt_rs = $Crypt3Des->encrypt($input);
        echo base64_encode($encrypt_rs);
        //var_dump($Crypt3Des->desUserKey($encrypt_rs));
        $rs = $Crypt3Des->decrypt($encrypt_rs);

        return View::make('api.api')->with( 'retData', $rs );
    }
  
}