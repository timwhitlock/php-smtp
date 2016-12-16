<?php
/**
 * php-smtp
 * @author Tim Whitlock
 * @license MIT
 */



/**
 * Line break character to send in SMTP requests
 */
define( 'SMTP_CRLF', "\r\n" );

defined('SMTP_DEBUG') or define('SMTP_DEBUG',false);
 
 
 
/**
 * SMTP socket connection
 */
class SMTP {
    
    /**
     * @var string
     */
    private $smtpHelo;
    
    /**
     * @var string mail server host
     */
    private $smtpHost;
    
    /**
     * @var string mail server port, defaults to 25
     */
    private $smtpPort = '25';
    
    /**
     * @var string security type (ssl|tls)
     */
    private $smtpSecure = '';
    
    /**
     * @var int socket timeout (seconds)
     */
    private $smtpTimeout = 10;
    
    /**
     * @var string
     */
    private $authUser;
        
    /**
     * @var string
     */
    private $authPass;
    
    /**
     * @var SMTPSocket
     */
    private $Socket;
    

    /**
     * 
     */
    public function __destruct(){
        $this->disconnect();
    }
    
    

    /**
     * @param string host
     * @param string optional port, defaults to 25
     * @param string optional security type (tls|ssl)
     * @return void
     */
    public function set_host( $host, $port = '25', $sec = '' ){
        $this->smtpHost = $host;
        $this->smtpPort = $port;
        // @todo security is untested 
        if( $sec ){
            switch( $sec ){
                case 'tls':
                case 'ssl':
                    $this->smtpSecure = $sec;
                    break;
                default:
                    trigger_error('Unsupported security type', E_USER_WARNING );
            }
        }
    }
    
    
    /**
     * @return string
     */
    private function guess_hostname(){
        if( isset($_SERVER['SERVER_NAME']) ){
            $hostname = $_SERVER['SERVER_NAME'];
        }
        else {
            $hostname = trim(`hostname`);
        }
        if( ! $hostname ){
            $hostname = 'localhost.localdomain';
        }
        return $hostname;
    }    
    
    
    /**
     * @return void
     */
    public function set_auth( $user, $pass ){
        $this->authUser = $user;
        $this->authPass = $pass;
    }

    
    
    /**
     * @param int
     * @return void
     */
    public function set_timeout( $secs ){
        $this->smtpTimeout = (int) $secs;
    }

    
    
    /**
     * Get/set hostname for HELO SMTP handshake
     * @return string
     */
    public function helo( $name = null ){
        if( is_string($name) ){
            $this->smtpHelo = $name;
        }
        else if( is_null($this->smtpHelo) ){
            $this->smtpHelo = $this->guess_hostname();
        }
        return $this->smtpHelo;
    }
    
    
    
    /**
     * Close SMTP socket, if open
     */
    private function disconnect(){
        if( $this->Socket ){
            $bye = $this->Socket->quit();
            $this->Socket = null;
        }
        return true;
    }
    

    
    /**
     * Connect to SMTP server
     * @return SMTPSocket
     */
    private function connect(){
        if( isset($this->Socket) && $this->Socket instanceof SMTPSocket ){
            return $this->Socket;
        }
        // configure SMTP socket for connecting to mail server
        $this->Socket = new SMTPSocket;
        if( $this->smtpSecure === 'ssl' ){
            $host = 'ssl://'.$this->smtpHost;
        }
        else{
            $host = $this->smtpHost;
        }
        // Attempt connection
        // @todo rate limiting / throttling? 
        if( ! $this->Socket->open( $host, $this->smtpPort, $this->smtpTimeout ) ){
            $this->Socket = null;
            throw new Exception('Failed to connect to SMTP host '.$host.':'.$this->smtpPort);
        }
        // Wait for banner
        $reply = $this->Socket->read( $code );
        if( $code !== 220 ){
            throw new SMTPException( $reply, $code );
        }
        // Say helo
        $helo = sprintf('EHLO %s', $this->helo() );
        $reply = $this->Socket->write_line( $helo, $code );
        if( $code !== 250 ){
            throw new SMTPException( $reply, $code ); 
        }
        // Start TLS
        while( $this->smtpSecure === 'tls' ){
            $this->Socket->write_line( 'STARTTLS', $code );
            if( $code === 220 ){
                // repeat HELO
                $this->Socket->write_line( $helo, $code );
                if( $code === 250 && $this->Socket->start_tls() ){
                    break; // TLS ok.
                }
            }
            trigger_error('Failed to use TLS .. trying again without');
            $this->disconnect();
            $this->smtpSecure = '';
            return $this->connect();
        }
        // Authenticate if user name is set
        while( $this->authUser ){
            // ascertain accepted auth protocols to try in order of priority
            if( ! preg_match('/250-AUTH( |=)([\-\w ]+)/i', $reply, $r ) || empty($r[2]) ){
                trigger_error('No auth mechanisms declared by server', E_USER_NOTICE );
                break;
            }
            $auths = explode( ' ', strtoupper($r[2]) );
            // Use CRAM-MD5 if available
            if( in_array('CRAM-MD5', $auths, true ) ){
                // declare that we wish to authenticate
                $reply = $this->Socket->write_line('AUTH CRAM-MD5', $code );
                if( $code === 334 && preg_match('/^334 (.+)/', $reply, $r ) ){
                    $challenge = base64_decode( $r[1] );
                    $userhash = base64_encode( $this->authUser.' '. hash_hmac('md5', $challenge, $this->authPass, false ) );
                    $reply = $this->Socket->write_line( $userhash, $code );
                    if( $code === 235 ){
                        break;
                    }
                }
                trigger_error('AUTH CRAM-MD5 failed', E_USER_NOTICE );
            }
            // else attempt simple LOGIN method 
            if( in_array('LOGIN', $auths, true ) ){
                $reply = $this->Socket->write_line('AUTH LOGIN', $code );
                if( $code !== 334 ){
                    throw new SMTPException( $reply, $code );
                }
                $reply = $this->Socket->write_line( base64_encode($this->authUser), $code );
                if( $code === 334 ){
                    // send password
                    $reply = $this->Socket->write_line( base64_encode($this->authPass), $code );
                    if( $code === 235 ){
                        break;
                    }
                }
                trigger_error('AUTH LOGIN failed', E_USER_NOTICE );
            }
            // finally attempt plain method
            if( in_array('PLAIN', $auths, true ) ){
                $userhash = base64_encode( sprintf("\0%s\0%s\0", $this->authUser, $this->authPass ) );
                $reply = $this->Socket->write_line('AUTH PLAIN '.$userhash, $code );
                if( $code !== 235 ){
                    trigger_error('AUTH PLAIN failed', E_USER_NOTICE );
                }
                break;
            }
            // No declared auth methods available
            trigger_error('No supported authentication method available', E_USER_NOTICE );
            break;
        }
        return $this->Socket;
    }
    
    
    
    
    /**
     * Prepare after connection by declaring sender
     * @return SMTP
     */
    public function init( array $rcpts = array(), $retpath = '' ){
        try {
            // Establish who the mail will be from (Return-path)
            if( ! $retpath ){
                $retpath = get_current_user().'@'.$this->helo();
            }
            // We should be ok to send this data through socket now ..
            // Get existing, or open new socket for sending
            $Socket = $this->connect();
            if( ! ( $Socket instanceof SMTPSocket ) ){
                throw new Exception('SMTP::connect failed, but did not return an error'); // <- paranoid
            }
            // Start single mail transaction by declaring sender
            $reply = $Socket->write_line( sprintf('MAIL FROM: <%s>', $retpath ), $code );
            if( $code !== 250 ){
                throw new SMTPException( $reply, $code );
            }
            // Add all recipients to envelope
            $rejected = 0;
            foreach( $rcpts as $i => $rcpt ){
                try {
                    $this->to( $rcpt );
                }
                catch( SMTPException $Ex ){
                    $rejected++;
                    trigger_error( $Ex->getMessage(), E_USER_NOTICE );
                }
            }
            if( $rejected  ){
                // @todo should we continue if some recipients only were rejected?
                throw new Exception('SMTP server rejected '.$rejected.' recipients' );
            }
            // server ready for ::to() or ::data()
            return $this;
        }
        catch( Exception $Ex ){
            $this->disconnect();
            throw $Ex;
        }
    }    



    /**
     * Declare a recipient
     * @param string email address
     * @return SMTP
     */
    public function to( $rcpt ){
        $Socket = $this->connect();
        $reply = $Socket->write_line( sprintf('RCPT TO: <%s>', $rcpt ), $code );
        if( $code !== 250 ){
            throw new SMTPException( $reply, $code );
        }        
        return $this;
    }




    /**
     * Write email data
     * @return SMTP
     */
    public function data( $data ){
        try {
            $Socket = $this->connect();
            // Prepare to send the full message with headers
            $reply = $Socket->write_line('DATA', $code );
            if( $code !== 354 ){
                throw new SMTPException( $reply, $code );
            }        
            $Socket->write( $data );
            // end data input with correct character sequence
            $reply = $Socket->write_line( SMTP_CRLF.'.', $code );
            if( $code !== 250 ){
                throw new SMTPException( $reply, $code );
            }
            // Keeping socket open for another email
            return $this;
        }
        catch( Exception $Ex ){
            $this->disconnect();
            throw $Ex;
        }
    }
    
    
}
 
 
 
 

/**
 * OO socket wrapper
 */
class SMTPSocket {
    
    /**
     * @var resource
     */
    private $fp;

    
    /**
     * Graceful close on desctruct
     */
    public function __destruct(){
       $this->quit();
    }

    
    /**
     * 
     */
    function open( $addr, $port, $timeout ){
        $this->fp = fsockopen( $addr, $port, $errno, $errstr, $timeout );
        return is_resource( $this->fp );
    }
    
    
    
    /**
     * Write data to the SMTP socket input stream
     * @param string
     * @return int
     */
    public function write( $data ){
        if( SMTP_DEBUG ){
            echo "> ", implode("\n> ", preg_split('/(\r\n|\n)/',$data) ), "\n";
        }
        return fputs( $this->fp, $data );
    }   
    
    

    /**
     * Write data to the SMTP socket with a trailing line break and get resonse straight away
     * @param string
     * @return string
     */
    public function write_line( $data, &$code ){
        $data and $this->write( $data );
        $this->write( SMTP_CRLF );
        return $this->read( $code );
    }
    
    
    
    /**
     * @param int reference for SMTP reply code
     * @return string
     */
    public function read( &$code ){
        $code = 0;
        // hold here for response, timeout passed in fsockopen
        stream_set_blocking( $this->fp, true );
        $response = '';
        // get bytes until we have either a response code or an end of file
        while ( ! feof($this->fp) ) {
            $str = fgets( $this->fp, 515 );
            $response .= $str;
            if( preg_match('/^(\d{3})( |$)/', $str, $r) ){
                $code = (int) $r[1];
                break;
            }
        }
        if( SMTP_DEBUG ){
            echo "< ", implode("\n< ", preg_split('/(\r\n|\n)/',$response) ), "\n";
        }
        return $response;
    }
    
    
    
    /**
     * @return void;
     */
    public function quit(){
        if( is_resource($this->fp) ){
            $bye = $this->write_line('QUIT', $code ); // <- code will be 221, but we're closing anyway
            fclose($this->fp);
            return trim($bye);
        }
        $this->fp = null;
        return '';
    }
    
    
    
    /**
     * @return bool
     */
    public function start_tls(){
        return stream_socket_enable_crypto( $this->fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT );
    }
    
    

}


class SMTPException extends Exception {
    
    
}


