<?php

/**
 * Provides an interface to issue commands to a remote WHM server.
 * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/XmlApi
 * @author Jamie Chung
 * @email jamie@clientexec.com
 * @version 7.08.2010
 */
class CpanelApi
{
	protected $host;
	protected $username;
	protected $hash;
	protected $ssl = false;
	var $port;
	var $schema;
	var $type = 'json';
	var $result;
	var $request;
	var $url;

	/**
	 * Let's start her up!
	 * @param string $host Host name of server
	 * @param string $username Username with WHM privileges
	 * @param string $hash Access hash
	 * @param boolean $ssl Use an SSL connection
	 * @param string $type Output type
	 */
	public function __construct ( $host, $username, $hash, $ssl = false, $type = 'json' )
	{
		$this->host = $host;
		$this->username = $username;
		$this->hash = $hash;
		$this->ssl = $ssl;
		$this->port = ( $ssl == true ) ? 2087 : 2086;
		$this->schema = ( $ssl == true ) ? 'https://' : 'http://';
		$this->type = 'json';
	}

	/**
	 * Makes a request through the cPanel API
	 * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/XmlApi
	 * @param string $function
	 * @param array $params
	 * @return boolean
	 */
	public function call ( $function, $params = array() )
	{
		if ( !function_exists('curl_init') )
		{
			CE_Lib::debug(1,'cURL is required in order to connect to cPanel');
			throw new CE_Exception('cURL is required in order to connect to cPanel');
		}

		$this->url = $url = $this->schema . $this->host .':'. $this->port .'/json-api/' . $function . $this->build($params);

		$ch = curl_init ( $url );
		curl_setopt ( $ch, CURLOPT_SSL_VERIFYHOST, false );
		curl_setopt ( $ch, CURLOPT_SSL_VERIFYPEER, false );
		curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
		curl_setopt ( $ch, CURLOPT_CONNECTTIMEOUT, 3 );
		curl_setopt ( $ch, CURLOPT_HEADER, false );

		$headers = array();
		$headers[0] = "Authorization: WHM {$this->username}:" . preg_replace("'(\r|\n)'","",$this->hash);

		curl_setopt ( $ch, CURLOPT_HTTPHEADER, $headers );

		$data = curl_exec ( $ch );

		if ( $data === false )
		{
			$error = "Cpanel API Request (".$function.") / cURL Error: ".curl_error($ch);
			CE_Lib::log(1,$error);
			throw new Exception($error);
		}

		$result = $this->result = json_decode($data);

		$this->request = array ( 'url' => $this->url, 'function' => $function, 'params' => $params, 'raw' => $data, 'json' => $result);

		CE_Lib::log(3,'cPanel API Request: '.print_r($this->request,true));

		if ( !is_object($result) )
		{
            // invalid json... check raw for an SSL error
            if ( strpos($data, 'SSL encryption is required for access to this server') )
            {
                CE_Lib::log(1, "Error from cPanel: SSL encryption is required for access to this server.");
                throw new Exception ('Error from cPanel: SSL encryption is required for access to this server.');
            }

            throw new Exception("Cpanel call method: Invalid JSON please check your connection");
		}
		else if ( isset($result->data->result) && $result->data->result == 0 )
		{
			throw new CE_Exception("Cpanel returned an error.  ".$result->data->reason);
		}
		else if ( isset($result->status) && $result->status == 0 )
		{
			throw new CE_Exception("Cpanel returned an error.  ".$result->statusmsg);
		}
		else if ( isset($result->result) && (isset($result->result[0])) && $result->result[0]->status == 0 )
		{
			throw new CE_Exception("Cpanel returned an error.  ".$result->result[0]->statusmsg);
		}

		return $result;
	}

	/**
	 * Builds an array suited for a CpanelAPI request.
	 * @param array $params Key => Value array of parameters to send as the request.
	 * @return string Properly built http query string
	 */
	private function build ( $params = array() )
	{
		if ( count($params) == 0 )
		{
			return '';
		}

		$queryString = array();
		foreach ( $params as $k => $v )
		{
			$queryString[] = $k .'='. $v;
		}

		return '?'.implode('&', $queryString);
	}

	/**
	 * Gets all packages available to the cpanel user.
	 * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/ListPackages
	 * @return Array of packages (key = package name, index = package array)
	 */
	public function packages ()
	{
		$result = $this->call('listpkgs');
		$packages = array();

		foreach ( (array) $result->package as $p )
		{
			$packages[trim($p->name)] = $p;
		}

		return $packages;
	}

	/**
	 * Gets all the accounts available to the cpanel user.
	 * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/ListAccounts
	 * @return Array of accounts (key = account username, index = account array)
	 */
	public function accounts ()
	{
		$result = $this->call('listaccts');
		$accounts = array();

		foreach ( (array) $result->acct as $a )
		{
			$accounts[$a->user] = $a;
		}

		return $accounts;
	}

	/**
	 * Gets all the suspended accounts.
	 * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/ListSuspended
	 */
	public function suspended ()
	{
		$result = $this->call('listsuspended');

		$accounts = array();

		foreach ( (array) $result->accts as $a )
		{
			$accounts[$a->user] = $a;
		}

		return $accounts;
	}

	/**
	 * Gets the current WHM/cPanel version on the server.
	 * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/DisplaycPanelWHMVersion
	 * @return string Current WHM version
	 */
	public function version ()
	{
		$result = $this->call('version');
		return $result->version;
	}
}

?>