<?php
use Illuminate\Support\Facades\Lang;
#token有效时长，默认为15天
define( 'TOKEN_TIMEOUT', Config::get( 'MyGlobal.tokenTimeout' ) );
#登录请求超时时长
define( 'CLIENT_LOGIN_TIMEOUT', Config::get( 'MyGlobal.clientLoginTimeOut' )  );




/**
 *
 * ClassName: MyAuthModel
 *
 * description...
 *
 * @author hejigui <jigui@staff.sina.com.cn>
 *
 */
class MyAuth {

    /**
     * token的过期时长 单位为秒
     *
     * @var integer
     */
    private $_token_timeout_seconds = TOKEN_TIMEOUT;

    /**
     * ldap 服务器信息
     *
     * @var array
    */
    
    private $_ldap_server = array();
    
    
    private $retData = array( 'retCode'=>1, 'retMsg'=>'success', 'data'=>array() );


    public function __construct()
    {
        
        $this->_ldap_server = Config::get( 'MyGlobal.ldap' );
    }

    /**
     * xxxxxxx
     *
     * @access public
     * @return string $mixed
    */
    public function getRetData() {
        return $this->retData;
    }


    /**
     * 接口请求有效性验证
     *
     * 1 获取此用户token信息
     * 2 验证token信息
     * 3 更新token信息
     *
     * @access public
     * @param string $user 用户请求接口时.上传的user名称 [Must]
     * @param string $token 用户请求接口时.上传的token值 [Must]
     * @param string $deviceID 用户请求接口时.带上的header信息 [Must]
     * @return bool 验证成功返回true.否则返回false
     */
    public function apiCheckInvalid($user,$token,$deviceID) {
        if(empty($user) || empty($token) || empty($deviceID)) {
            $this->retData['retCode'] = 1001;
            $this->retData['retMsg'] = Lang::get('staticVariable.auth.1001');
            $this->retData['data'] = array( 'user'=>$user,'token'=>$token, 'deviceID'=>$deviceID );
            return false;
        }

        //1 获取此用户token信息
        if(false == ($token_info = $this->getToken($user))) {
            $this->retData['retCode'] = 1002;
            $this->retData['retMsg'] = Lang::get('staticVariable.auth.1002');
            $this->retData['data'] = array( 'user'=>$user,'token'=>$token, 'deviceID'=>$deviceID );
            return false;
        }

        //2 验证token信息
        if($token_info['deviceID'] != $deviceID) {
            $this->retData['retCode'] = 1003;
            $this->retData['retMsg'] = Lang::get('staticVariable.auth.1003');
            $this->retData['data'] = array( 'user'=>$user,'token'=>$token, 'deviceID'=>$deviceID );
            return false;
        }

        //3 更新token信息
        if(false == ($this->saveToken($user,$token_info['token'],$token_info['timestamp'],$token_info['deviceID']))) {
            $this->retData['retCode'] = 1004;
            $this->retData['retMsg'] = Lang::get('staticVariable.auth.1004');
            $this->retData['data'] = array( 'user'=>$user,'token'=>$token, 'deviceID'=>$deviceID );
            return false;
        }

        return true;
    }


    /**
     * 用户身份验证
     *
     * 1 解码客户端信息
     * 2 验证客户端上传的信息是否有效
     * 	a)时间是否超时
     * 	b)用户是否存在
     * 	c)密码是否正确
     * 3 验证用户信息成功 生成token信息.并保存
     *
     * @access public
     * @param string $_userKey 客户端上传的 加密信息 [Must]
     * @return bool $rs 成功返回 true,否则返回false
     */
    public function auth($_userKey) {
        if(empty($_userKey)) {
            $this->retData['retCode'] = 2001;
            $this->retData['retMsg'] = Lang::get('staticVariable.auth.2001');
            $this->retData['data'] = array( 'userKey'=>$_userKey );
            return false;
        }

        // 1 解码客户端信息
        $_userKey = base64_decode($_userKey);
        if(false == ($client_info = $this->desUserKey($_userKey))) {
            $this->retData['retCode'] = 2002;
            $this->retData['retMsg'] = Lang::get('staticVariable.auth.2002');
            $this->retData['data'] = array( 'userKey'=>$_userKey );
            return false;
        }


        //2 验证客户端上传的信息是否有效
        if($client_info['timestamp'] < (time()- CLIENT_LOGIN_TIMEOUT)) {
            $this->retData['retCode'] = 2003;
            $this->retData['retMsg'] = Lang::get('staticVariable.auth.2003');
            $this->retData['data'] = array( 'userKey'=>$_userKey );
            return false;
        }

        if(false == ($this->getUserInfo($client_info['userName']))) {
            $this->retData['retCode'] = 2004;
            $this->retData['retMsg'] = Lang::get('staticVariable.auth.2004');
            $this->retData['data'] = array( 'userKey'=>$_userKey );
            return false;
        }

        if(false == ($this->authByLdap($client_info['userName'],$client_info['passwd']))) {
            $this->retData['retCode'] = 2005;
            $this->retData['retMsg'] = Lang::get('staticVariable.auth.2005');
            $this->retData['data'] = array( 'userKey'=>$_userKey );
            return false;
        }


        //3 验证用户信息成功 生成token信息.并保存
        if(false == ($token = $this->makeToken($client_info['userName'],$client_info['passwd'],$client_info['timestamp']))) {
            $this->retData['retCode'] = 2006;
            $this->retData['retMsg'] = Lang::get('staticVariable.auth.2006');
            $this->retData['data'] = array( 'userKey'=>$_userKey );
            return false;
        }

        return $this->saveToken($client_info['userName'],$token,$client_info['timestamp'],$client_info['deviceID']);
    }

    /**
     * 解码客户端上传的 加密信息
     * 解密成功得到 array('userName'=>'xxx','passwd'=>'xxx','timestamp'=>xxx,'deviceID'=>'xxx')
     * 解密失败返回false
     *
     * @access public
     * @param string $_userKeyset 客户端上传的 加密信息  [Must]
     * @return array $mix
     */
    private function desUserKey($_userKey) {
        if(empty($_userKey)) {
            Log::info('参数错误!');
            return false;
        }

        $Crypt3Des = App::make('Crypt3Des');
        if(false == ($decrypt_rs = $Crypt3Des->decrypt($_userKey))) {
            Log::info('userKey!('.$_userKey.')解码失败!');
            return false;
        }

        $decrypt_rs = explode(',',$decrypt_rs);
        if(empty($decrypt_rs[0]) || empty($decrypt_rs[1]) || empty($decrypt_rs[2]) || empty($decrypt_rs[3])) {
            Log::info('userKey!('.$_userKey.')解码后值无效!');
            return false;
        }

        return array('userName'=> $decrypt_rs[0],'passwd'=> $decrypt_rs[1],'timestamp'=> $decrypt_rs[2],'deviceID'=> $decrypt_rs[3]);
    }

    /**
     * 根据用户提供的用户名.检查是否合法
     * 检查失败返回false
     *
     * @access public
     * @param string $userName xxxxx [Must]
     * @return array $mixed
     */
    private function getUserInfo($userName) {
        $userInfo = DB::select('select * from userinfo where userName=?',array($userName));
        if(empty($userInfo)) {
            Log::info('取用户信息失败('.$userName.')!');
            return false;
        }

        return $userInfo;
    }

    /**
     * 根据用户提供的用户名/密码.
     * 检查ldap用户是否正确
     *
     * @access public
     * @param string $userName xxxxx [Must]
     * @param string $passwd xxxxxx [Must]
     * @return bool 成功返回ture,失败返回false
     */
    private function authByLdap($userName,$passwd) {
        if (empty($userName) || empty($passwd)) {
            Log::info('参数无效!');
            return false;
        }

        $sLdapServer = 'ldap://'.$this->_ldap_server['ip'];
        if(false == ($oLdapConn = ldap_connect($sLdapServer, $this->_ldap_server['port'])))
        {
            Log::info('ldap连接无效，ldapServer='.$this->_ldap_server['ip'].',ldapport='.$this->_ldap_server['port']);
            return false;
        }
        $ldap_binddn = "CN=adrdgitlab,OU=ldap,OU=adminaccount,DC=staff,DC=sina,DC=com,DC=cn";
        $ldap_passwd = "yNN71B92-jJ*RFu";

        if(false == (@ldap_bind($oLdapConn, $ldap_binddn, $ldap_passwd))) {
            Log::info('ldap连接后bind失败，ldapServer='.$this->_ldap_server['ip'].',ldapport='.$this->_ldap_server['port']);
            ldap_close($oLdapConn);
            return false;
        }

        $ldap_basedn = "OU=SINA,DC=staff,DC=sina,DC=com,DC=cn";
        $ldap_filter = '(samaccountname=' . $userName . ')';

        if(false == ($ldap_search_rs = @ldap_search($oLdapConn, $ldap_basedn, $ldap_filter))){
            Log::info('ldap连接后search失败，ldapServer='.$this->_ldap_server['ip'].',ldapport='.$this->_ldap_server['port'],',userName='.$userName);            
            ldap_close($oLdapConn);
            return false;
        }

        if(false ==($user_arr = @ldap_get_entries($oLdapConn, $ldap_search_rs))) {
            Log::info('ldap连接后get_entries失败，ldapServer='.$this->_ldap_server['ip'].',ldapport='.$this->_ldap_server['port']);
            ldap_close($oLdapConn);
            return false;
        }

        if($user_arr["count"] < 1) {
            Log::info('ldap数据count小于1，ldapServer='.$this->_ldap_server['ip'].',ldapport='.$this->_ldap_server['port']);      
            ldap_close($oLdapConn);
            return false;
        }

        $user_binddn = $user_arr[0]["dn"];
        if(false == ($ub = @ldap_bind($oLdapConn, $user_binddn, $passwd))){
            Log::info('ldap用户密码错误，ldapServer='.$this->_ldap_server['ip'].',ldapport='.$this->_ldap_server['port'].'，userName='.$userName.',passwd='.$passwd);
            ldap_close($oLdapConn);
            return false;
        }

        ldap_close($oLdapConn);
        return true;
    }

    /**
     * 根据用户提供的信息生成token
     * 注意:此处生成token的算法/因子要与客户端保持一致
     *
     * @access public
     * @param string $user xxxxx [Must]
     * @param array $passwd xxxxxx [Must]
     * @param int $timestamp 注意:此处时间戳为客户端提交上来的客户端. [Must]
     * @return string $mixed
     */
    private function makeToken($user,$passwd,$timestamp) {
        if(empty($user) || empty($passwd) || empty($timestamp)) {
            Log::info('参数无效!');
            return false;
        }

        $key = "{$user},{$passwd},{$timestamp}";
        return md5(sha1($key));
    }

    /**
     * 保存token信息
     * 缓存值格式为:
     * user:json_encode(array('token'=>$token,'timestamp'=>$timestamp,'deviceID'=>$deviceID))
     * 其实这里timestamp存不存都可以...暂时先存.
     *
     *
     * @access public
     * @param string $user 用户名称..用于保存cache时..作为值的key [Must]
     * @param string $token xxxxxx [Must]
     * @param string $timestamp 计算token时..使用的timestamp [Must]
     * @param string $deviceID 计算token时..客户端SN号 [Must]
     * @return bool 保存成功返回 true,否则返回false
     */
    private function saveToken($user,$token,$timestamp,$deviceID) {
        if(empty($user) || empty($token) || empty($timestamp) || empty($deviceID)) {
            Log::info('参数无效!');
            return false;
        }

        $redisObj = new Redis();
        $redisObj->connect('redis.monitor.weibo.cn',6379);

        $value_string = json_encode(array('token'=>$token,'timestamp'=>$timestamp,'deviceID'=>$deviceID));
        $value = $redisObj->set($user, $value_string,$this->_token_timeout_seconds);
        $redisObj->close();
        return $value;
    }

    /**
     * 获取保存的token信息
     *
     * @access public
     * @param string $user xxxxx [Must]
     * @return array $rs 格式如:array('token'=>$token,'timestamp'=>$timestamp,'deviceID'=>$deviceID)
     */
    private function getToken($user) {
        if(empty($user)) {
            Log::info('参数无效!');
            return false;
        }

        $redisObj = new Redis();
        $redisObj->connect('redis.monitor.weibo.cn',6379);
        if(false == ($rs = $redisObj->get($user))) return false;
        $redisObj->close();

        return json_decode($rs,true);
    }
}
// ClassName MyAuthModel End



























/*

Class MyAuth{
    private static $retData;
    private static $userKey;
    
    public function getUserInfo( $userName )
    {
        $userInfo = DB::select('select * from User where userName=?',$userName);
        return $userInfo;
    }
    static public function desUserKey( $_userKey )
    {
        self::$userKey = $_userKey;
        return array(
            'userName'=>'sqj0213',
            'passwd'=>'asdfasf',
            'timestamp'=>time(),
            'deviceID'=>'1234567890'
        );
        
    }
    static public function getRetData()
    {
        if ( Empty( self::$retData ) )
            self:$retData = array('retCode'=>1, 'retMsg'=>Lang::get('staticVariable.auth.succ'));
        return json_encode( self::$retData );
    }
    
    static public function loginCheckTimeOut( $clientTimeStamp )
    {
        if ( ( time() - $clientTimeStamp ) > CLIENT_LOGIN_TIMEOUT )
        {
            self::$retData[ 'retCode' ] = -1;
            self::$retData[ 'retMsg' ] = Lang::get('staticVariable.auth.timeout');
            self::$retData[ 'userKey' ] = self::$userKey;
            return False;
        }
        return True;
    }
    
   static public function loginCheckDeviceID( $deviceID )
    {
        if ( Request::header( 'deviceID' ) !== $deviceID )
        {
            self::$retData[ 'retCode' ] = -1;
            self::$retData[ 'retMsg' ] = Lang::get('staticVariable.auth.invalid');
            self::$retData[ 'userKey' ] = self::$userKey;
            return False;
        }
        return True;
    }
    
    public function auth( $userName,$passwd )
    {
        if ( 1 === 1 )
        {
            return True;
        }
        return false;
    }
    
    public function checkValid( $token )
    {

    }
    
    public function getServerToken( $userName )
    {
        $redisObj = Redis::connection();
        $serverTokenData = json_decode( $redisObj->get($userName) );
        $redisObj->close();
        return $serverTokenData;
    }
    
    public function saveServerToken( $tokenData )
    {
        $redisObj = Redis::connection();
        if ( $redisObj->set( $tokenData[ 'userName' ], json_encode( $tokenData ) ) )
        {
            $redisObj->close();
            return False;
        }
        if ( $redisObj->expire( $tokenData[ 'userName' ], TOKEN_TIMEOUT))
        {
            $redisObj->close();
            return False;
        }
        return True;
    }
}
*/
