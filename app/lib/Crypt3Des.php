<?php
/**
* 
* PHP版3DES加解密类
*
* 可与java的3DES(DESede)加密方式兼容
*
* @Author: Luo Hui (farmer.luo at gmail.com)
*
* @version: V0.1 2008.12.04
*
*/
class Crypt3Des
{    
    public $key    = "01234567890123456789012345678912";
    public $iv    = "23456789"; //like java: private static byte[] myIV = { 50, 51, 52, 53, 54, 55, 56, 57 };
    
    //加密
    public function encrypt($input)
    {
        $input = $this->padding( $input );
        $key = base64_decode($this->key);
        $td = mcrypt_module_open( MCRYPT_3DES, '', MCRYPT_MODE_CBC, '');
        //使用MCRYPT_3DES算法,cbc模式
        mcrypt_generic_init($td, $key, $this->iv);
        //初始处理
        $data = mcrypt_generic($td, $input);
        //加密
        mcrypt_generic_deinit($td);
        //结束
        mcrypt_module_close($td);
        $data = $this->removeBR(base64_encode($data));
        return $data;
    }
    public function init( $_key, $_iv )
    {
    	$this->key = $_key;
    	$this->iv = $_iv;
    	
    }
    //解密
    public function decrypt($encrypted)
    {
        $encrypted = base64_decode($encrypted);
        $key = base64_decode($this->key);
        $td = mcrypt_module_open( MCRYPT_3DES,'',MCRYPT_MODE_CBC,'');
        //使用MCRYPT_3DES算法,cbc模式
        mcrypt_generic_init($td, $key, $this->iv);
        //初始处理
        $decrypted = mdecrypt_generic($td, $encrypted);
        //解密
        mcrypt_generic_deinit($td);
        //结束
        mcrypt_module_close($td);
        $decrypted = $this->removePadding($decrypted);
        return $decrypted;
    }
    
    //填充密码，填充至8的倍数
    public function padding( $str )
    {
        $len = 8 - strlen( $str ) % 8;
        for ( $i = 0; $i < $len; $i++ )
        {
            $str .= chr( 0 );
        }
        return $str ;
    }
    
    //删除填充符
    public function removePadding( $str )
    {
        $len = strlen( $str );
        $newstr = "";
        $str = str_split($str);
        for ($i = 0; $i < $len; $i++ )
        {
            if ($str[$i] != chr( 0 ))
            {
                $newstr .= $str[$i];
            }
        }
        return $newstr;
    }
    
    //删除回车和换行
    public function removeBR( $str ) 
    {
        $len = strlen( $str );
        $newstr = "";
        $str = str_split($str);
        for ($i = 0; $i < $len; $i++ )
        {
            if ($str[$i] != '\n' and $str[$i] != '\r')
            {
                $newstr .= $str[$i];
            }
        }
    
        return $newstr;
    }
}
/*
//test
$input = "1qaz2ws";
echo "plainText:" . $input."<br/>";
$crypt = new Crypt3Des();
echo "Encode:".$crypt->encrypt($input)."<br/>";
echo "Decode:".$crypt->decrypt($crypt->encrypt($input));
*/
?>

