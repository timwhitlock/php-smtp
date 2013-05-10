<?php
/**
 * Example, just tests for valid mailboxes and quits.
 */

define('SMTP_DEBUG', true ); 

require __DIR__.'/php-cli/cli.php'; 
require __DIR__.'/../smtp.php'; 
 
   
// configure SMTP host
$mx = 'gmail-smtp-in.l.google.com'; 

// mailboxes to sniff.
$to[] = 'abc@gmail.com';
$to[] = 'def@gmail.com';

// connection may fail if recipients not valid
cli::log('Connecting to %s', $mx );
$conn = new smtp;
$conn->set_host( $mx );
$conn->init( $to );

unset( $conn );
cli::log('Done');

