<?php

require_once 'newedge/classes/NE_MailGateway.php';
require_once 'modules/admin/models/ServerPlugin.php';
require_once dirname(__FILE__).'/CpanelApi.php';

/**
 * cPanel Plugin for ClientExec
 * @package Plugins
 * @version August.07.2010
 * @lastAuthor Jamie Chung
 * @email jamie@clientexec.com
 */
class PluginCpanel extends ServerPlugin
{
	var $api;

	/**
	 * Sets up the CpanelApi object in order to make requests to the server.
	 * @param <type> $args Standard set of arguments in order to make API request.
	 */
	public function setup ( $args )
	{
		if ( isset($args['server']['variables']['ServerHostName']) && 
			isset($args['server']['variables']['plugin_cpanel_Username']) && 
			isset($args['server']['variables']['plugin_cpanel_Access_Hash']) && 
			isset($args['server']['variables']['plugin_cpanel_Use_SSL']) ) {	
			$this->api = new CpanelApi ($args['server']['variables']['ServerHostName'],
                            $args['server']['variables']['plugin_cpanel_Username'],
                            $args['server']['variables']['plugin_cpanel_Access_Hash'],
                            $args['server']['variables']['plugin_cpanel_Use_SSL']);

			$this->api->setupLogger ( $this->logger, 4);
		} else {
			throw new Exception('Missing Server Credentials: please fill out all information when editing the server.');
		}
	}

	/**
	 * Emails cPanel server errors.
	 * @param String $name
	 * @param String $message
	 * @param Array $args
	 * @return string
	 */
	function email_error ( $name, $message, $args )
	{
		$error = "cPanel Account ".$name." Failed. ";
		$error .= "A email with the Details was sent to ". $args['server']['variables']['plugin_cpanel_Failure_E-mail'].'<br /><br />';

		if ( is_array($message) )
		{
			$message = implode ( "\n", trim($message) );
		}

		$this->logger->log(1, 'cPanel Error: '.print_r(array('type' => $name, 'error' => $error, 'message' => $message, 'params' => $args), true));

		if ( !empty($args['server']['variables']['plugin_cpanel_Failure_E-mail']) )
		{
			$mailGateway = new NE_MailGateway();
			$mailGateway->mailMessageEmail( $message,
							   $args['server']['variables']['plugin_cpanel_Failure_E-mail'],
							   "Cpanel Plugin",
							   $args['server']['variables']['plugin_cpanel_Failure_E-mail'],
							   "",
							   "Cpanel Account ".$name." Failure");
		}

		return $error.nl2br($message);
	}

	function getVariables()
	{
	   /* Specification
		    itemkey     - used to identify variable in your other functions
		    type        - text,textarea,yesno,password,hidden ( type hidden are variables used by CE and are required )
		    description - description of the variable, displayed in ClientExec
		    encryptable - used to indicate the variable's value must be encrypted in the database
	   */

        $variables = array (
                   /*T*/"Name"/*/T*/ => array (
                                        "type"=>"hidden",
                                        "description"=>"Used By CE to show plugin - must match how you call the action function names",
                                        "value"=>"CPanel"
                                       ),
                   /*T*/"Description"/*/T*/ => array (
                                        "type"=>"hidden",
                                        "description"=>/*T*/"Description viewable by admin in server settings"/*/T*/,
                                        "value"=>/*T*/"CPanel control panel integration"/*/T*/
                                       ),
                   /*T*/"Username"/*/T*/ => array (
                                        "type"=>"text",
                                        "description"=>/*T*/"Username used to connect to server"/*/T*/,
                                        "value"=>""
                                       ),
                   /*T*/"Access Hash"/*/T*/ => array (
                                        "type"=>"textarea",
                                        "description"=>/*T*/"Password used to connect to server"/*/T*/,
                                        "value"=>"",
                                        "encryptable"=>true
                                       ),
                   /*T*/"Use SSL"/*/T*/ => array (
                                        "type"=>"yesno",
                                        "description"=>/*T*/"Set NO if you do not have PHP compiled with cURL.  YES if your PHP is compiled with cURL<br><b>NOTE:</b>It is suggested that you keep this as YES"/*/T*/,
                                        "value"=>"1"
                                       ),
                   /*T*/"Failure E-mail"/*/T*/ => array (
                                        "type"=>"text",
                                        "description"=>/*T*/"E-mail address Cpanel error messages will be sent to"/*/T*/,
                                        "value"=>""
                                        ),
                   /*T*/"Actions"/*/T*/ => array (
                                        "type"=>"hidden",
                                        "description"=>/*T*/"Current actions that are active for this plugin per server"/*/T*/,
                                        "value"=>"Create,Delete,Suspend,UnSuspend"
                                       ),
                    /*T*/'reseller'/*/T*/  => array(
                                        'type'          => 'hidden',
                                        'description'   => /*T*/'Whether this server plugin can set reseller accounts'/*/T*/,
                                        'value'         => '1',
                                       ),
                    /*T*/'reseller-fieldset'/*/T*/  => array(
                                        'type'          => 'fieldset',
                                        'name'          => 'reseller-fieldset',
                                        'label'   => /*T*/'Reseller Account Specific Fields'/*/T*/,
                                        'description'   => /*T*/''/*/T*/,
                                        'value'         => '1',
                                       ),
                    /*T*/'reseller_acl_fields'/*/T*/ => array(
                                        'type'          => 'hidden',
                                        'description'   => /*T*/'ACL field for reseller account'/*/T*/,
                                        'value'         => array(
                                                                array('name' => 'acl-name', 'type' => 'text', 'label' => 'Reseller ACL Name', 'description' => /*T*/'If you have a predefined ACL List in WHM you wish to use, enter it here.'/*/T*/, 'belongsto' => 'reseller-fieldset'),
								array('name' => 'acl-rslimit-disk', 'type' => 'text', 'label' => 'Disk space in MB', 'description' => /*T*/'If you wish to set Disk space AND Bandwitdh as unlimited, leave this field empty.<br />if you wish to limit Bandwidth but not Disk Space, enter a very large number here'/*/T*/, 'belongsto' => 'reseller-fieldset'),
								array('name' => 'acl-rsolimit-disk', 'type' => 'check', 'label' => 'Disk space overselling allowed' , 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-rslimit-bw', 'type' => 'text', 'label' => /*T*/'Bandwidth in MB'/*/T*/, 'description' => /*T*/'If you wish to set Disk space AND Bandwitdh as unlimited, leave this field empty.<br />if you wish to limit Disk Space but not Bandwidth, enter a very large number here'/*T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-rsolimit-bw', 'type' => 'check', 'label' => /*T*/'Bandwidth overselling allowed'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-domain-quota', 'type' => 'text', 'label' => /*T*/'Domain quota'/*/T*/, 'belongsto' => 'reseller-fieldset'  ),
								array('name' => 'acl-list-accts', 'type' => 'check', 'label' => /*T*/'List Accounts'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-show-bandwidth', 'type' => 'check', 'label' => /*T*/'View Account Bandwidth Usage'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-create-acct', 'type' => 'check', 'label' => /*T*/'Account Creation'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-edit-account', 'type' => 'check', 'label' => /*T*/'Account Modification'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-suspend-acct', 'type' => 'check', 'label' => /*T*/'Account Suspension'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-kill-acct', 'type' => 'check', 'label' => /*T*/'Acccount Termination'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-upgrade-account', 'type' => 'check', 'label' => /*T*/'Account Upgrades'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-limit-bandwidth', 'type' => 'check', 'label' => /*T*/'Bandwidth Limiting Modification'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-edit-mx', 'type' => 'check', 'label' => /*T*/'Edit MX Entries'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-frontpage', 'type' => 'check', 'label' => /*T*/'Enabling/Disabling FrontPage Extensions'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-mod-subdomains', 'type' => 'check', 'label' => /*T*/'Enabling/Disabling SubDomains'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-passwd', 'type' => 'check', 'label' => /*T*/'Password Modification'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-quota', 'type' => 'check', 'label' => /*T*/'Quota Modification'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-res-cart', 'type' => 'check', 'label' => /*T*/'Reset Shopping Cart'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-ssl-gencrt', 'type' => 'check', 'label' => /*T*/'SSL CSR/CRT Generator'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-ssl', 'type' => 'check', 'label' => /*T*/'SSL Site Management'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-demo-setup', 'type' => 'check', 'label' => /*T*/'Turn an account into a demo account'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-rearrange-accts', 'type' => 'check', 'label' => /*T*/'Rearrange Accounts'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-clustering', 'type' => 'check', 'label' => /*T*/'Clustering'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-create-dns', 'type' => 'check', 'label' => /*T*/'Add DNS'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-edit-dns', 'type' => 'check', 'label' => /*T*/'Edit DNS'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-park-dns', 'type' => 'check', 'label' => /*T*/'Park DNS'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-kill-dns', 'type' => 'check', 'label' => /*T*/'Remove DNS'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-add-pkg', 'type' => 'check', 'label' => /*T*/'Add/Remove Packages'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-edit-pkg', 'type' => 'check', 'label' => /*T*/'Edit Packages'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-add-pkg-shell', 'type' => 'check', 'label' => /*T*/'Allow Creation of Packages With Shell Access'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-allow-unlimited-disk-pkgs', 'type' => 'check' , 'label' => /*T*/'Allow Creation of Packages with Unlimited Diskspace'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-allow-unlimited-pkgs', 'type' => 'check' , 'label' => /*T*/'Allow Creation of Packages with Unlimited Features'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-add-pkg-ip', 'type' => 'check', 'label' => /*T*/'Allow Creation of Packages With a Dedicated IP'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-allow-addoncreate', 'type' => 'check' , 'label' => /*T*/'Allow Creation of Packages with Addon Domains'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-allow-parkedcreate', 'type' => 'check', 'label' => /*T*/'Allow Creation of Packages With Parked Domains'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-onlyselfandglobalpkgs', 'type' => 'check' , 'label' => /*T*/'Allow creation of accounts with packages that are global or owned by this user'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-disallow-shell', 'type' => 'check', 'label' => /*T*/'Never allow creation of accounts with shell access'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-stats', 'type' => 'check', 'label' => /*T*/'View Account Statistics'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-status', 'type' => 'check', 'label' => /*T*/'View Server Status'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-restart', 'type' => 'check', 'label' => /*T*/'Restart Services'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-mailcheck', 'type' => 'check', 'label' => /*T*/'Mail Trouble Shooter'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-restftp', 'type' => 'check', 'label' => /*T*/'Resync Ftp Passwords'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								array('name' => 'acl-news', 'type' => 'check', 'label' => /*T*/'News Modification'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
								// keep this one last because it's too powerful, and better think about users security
								array('name' => 'acl-all', 'type' => 'check', 'label' => /*T*/'All Features (root access)'/*/T*/, 'belongsto' => 'reseller-fieldset' ),
                                                        ),
                                       ),
            /*T*/'package_addons'/*/T*/ => array(
                                        'type'          => 'hidden',
                                        'description'   => /*T*/'Supported signup addons variables'/*/T*/,
                                        'value'         => array(
                                                                'DISKSPACE', 'BANDWIDTH', 'SSL'
                                                                ),
                                       ),
	   );
	   return $variables;
	}

    /**
     * Checks if a plan exists.
     * @param String $plan to check against.
     * @param <type> $args
     * @return boolean
     */
    function CheckCpanelPlan($plan, $args)
    {
	    $this->setup($args);
	    $packages = $this->api->packages();
	    if ( is_array($packages) && isset($packages[$plan]) )
	    {
		    return true;
	    }
	    return false;
    }

    /**
     * Preps for account creation or update.
     * @param <type> $args
     * @return NE_Error
     */
    function validateCredentials($args)
    {
        //$this->setup($args);
        $args['package']['username'] = trim(strtolower($args['package']['username']));

        $errors = array();

        // Ensure that the username is not test and doesn't contain test
        if (strpos(strtolower($args['package']['username']), 'test') !== false) {
            if (strtolower($args['package']['username']) != 'test') {
                $args['package']['username'] = str_replace('test', '', $args['package']['username']);
            } else {
                $errors[] = 'Domain username can\'t contain \'test\'';
            }
        }

        // Username cannot start with a number
        if (is_numeric(mb_substr(trim($args['package']['username']), 0, 1))) {
            $args['package']['username'] = preg_replace("/^\d*/", '', $args['package']['username']);

            if (is_numeric(mb_substr(trim($args['package']['username']), 0, 1)) || strlen(trim($args['package']['username'])) == 0) {
                $errors[] = 'Domain username can\'t start with a number';
            }
        }

        // Username cannot contain a dash (-)
        if (strpos($args['package']['username'], "-") !== false) {
            $args['package']['username'] = str_replace("-", "", $args['package']['username']);
            $errors[] = 'Domain username can\'t contain dashes';
        }
        
        // Username cannot contain a space
        if (strpos($args['package']['username'], " ") !== false) {
            $args['package']['username'] = str_replace(" ", "", $args['package']['username']);
            $errors[] = 'Domain username can\'t contain spaces';
        }
		
        // Username cannot contain an underscore (_)
        if (strpos($args['package']['username'], "_") !== false) {
            $args['package']['username'] = str_replace("_", "", $args['package']['username']);
            $errors[] = 'Domain username can\'t contain underscores';
        }

        // Username cannot be greater than 8 characters
        if (strlen($args['package']['username']) > 8) {
            $args['package']['username'] = mb_substr($args['package']['username'], 0, 8);
        }
	else if ( strlen(trim($args['package']['username'])) <= 0 )
	{
		$errors[] = 'The cPanel username is blank.';
	}
	else if ( strlen(trim($args['package']['password'])) <= 0 )
	{
		$errors[] = 'The cPanel password is blank';
	}


	// Only make the request if there have been no errors so far.
	if ( count($errors) == 0 )
	{
		// if it's an update, skip username existance check
		// Only perform the request when we are not updating and we are not signinig up.
		/*if ((!isset($args['isUpdate']) || !$args['isUpdate']) && !NE_SIGNUP) {
			$accts = $this->api->accounts();

			$i = 1;
			while (isset($accts[$args['package']['username']])) {
				$args['package']['username'] = mb_substr($args['package']['username'], 0, 7).$i++;
			}
		}*/

		if (strpos($args['package']['password'], $args['package']['username']) !== false) {
			$errors[] = 'Domain password can\'t contain domain username';
		}
	}

        // Check if we want to supress errors during signup and just return a valid username
        if(isset($args['noError'])) {
            return $args['package']['username'];
        } else {

            if ( count($errors) > 0 )
                    {
                        $this->logger->log(4, "plugin_cpanel::validate::error: ".print_r($errors,true));
                            throw new Exception($errors[0]);
            }

            return $args['package']['username'];
        }
    }

	//plugin function called after account is activated
	function doCreate($args)
	{
		$userPackage = new UserPackage($args['userPackageId']);
		$this->create($this->buildParams($userPackage));
		return $userPackage->getCustomField("Domain Name") . ' has been created.';
	}

	/**
	  * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/CreateAccount
	  * @param <type> $args
	  * @return NE_Error
	  */
	function create($args)
	{
		$this->setup($args);
		$errors = array();

		//if (!$args['plugin_cpanel_Create'] == 1) return;
		if ( $args['package']['name_on_server'] == null ) {
			throw new Exception("Cpanel create method: This package is not tied to a Cpanel account");
		}

		// package add-ons handling
		if ( isset($args['package']['addons']['DISKSPACE']) ) {
			@$args['package']['acl']['acl-rslimit-disk'] += ((int)$args['package']['addons']['DISKSPACE']);
		}
		if ( isset($args['package']['addons']['BANDWIDTH']) ) {
			@$args['package']['acl']['acl-rslimit-bw'] += ((int)$args['package']['addons']['BANDWIDTH']) * 1024; // Convert from Gigs to MB
		}
		if ( isset($args['package']['is_reseller']) && isset($args['package']['addons']['SSL']) && $args['package']['addons']['SSL'] == 1) {
			$args['package']['acl']['acl-ssl'] = 1;
		}

		// Checks if the plan exists.
		if ( !$this->CheckCpanelPlan($args['package']['name_on_server'], $args) )
		{
			$error = "The package '{$args['package']['name_on_server']}' was not found on the server.";
			$errors[] = $this->email_error('Creation', $error, $args );
                        throw new Exception($error);
		}

		// Params array we pass to cPanel server.
		$params = array();
		$params['username'] = $args['package']['username'];
		$params['domain'] = $args['package']['domain_name'];
		$params['plan'] = urlencode($args['package']['name_on_server']);
		$params['password'] = $args['package']['password'];
		// Reseller Limits should not be set on shared hosting accounts
                //$params['quota'] = @$args['package']['acl']['acl-rslimit-disk'];
		//$params['bwlimit'] = @$args['package']['acl']['acl-rslimit-bw'];
		$params['contactemail'] = $args['customer']['email'];

		$request = $this->api->call('createacct', $params);

		if ( $request->result[0]->status != 1 )
		{
			$errors[] = $this->email_error('Creation', $request->result[0]->statusmsg, $args);
		}
		else if ( $request->result[0]->status == 1 )
		{
			// setup the reseller permissions if necessary
			if ( isset($args['package']['is_reseller']) && $args['package']['is_reseller']== 1 )
			{
                                $this->_addReseller($args);
				$this->_setResellerACLs($args);
			}
		}
		else
		{
			$errors[] = "Error connecting to cPanel server";
		}

		// Rather than returning an error object every time, just return it here.
		// Need to check if an actual error exists to avoid returning an error object on a success message
		if ( count($errors) > 0 )
		{
			$this->logger->log(4, "plugin_cpanel::create::error: ".print_r($errors,true));
			throw new Exception ( $errors[0] );
		}
		return;
	}

	function doUpdate($args)
	{
		$userPackage = new UserPackage($args['userPackageId']);
		$this->update($this->buildParams($userPackage, $args));
		return $userPackage->getCustomField("Domain Name") . ' has been updated.';
	}
	
	function update($args)
	{
		$this->setup($args);
		$args = $this->updateArgs($args);
		$errors = array();
		// Loop over changes array
		foreach ( $args['changes'] as $key => $value ) 
		{
			switch ( $key ) 
			{
				/**
				 * Change Username
				 * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/ModifyAccount
				 */
				case 'username':
					$request = $this->api->call('modifyacct', array('user' => $args['package']['username'], 'newuser' => $value));
					if ( $request->result[0]->status != 1 )
					{
						$errors[] = $this->email_error('Username Change', $request->result[0]->statusmsg, $args);
					}
					// Internal fix, incase we are also changing the domain name.
					$args['package']['username'] = $value;
					break;

				/**
				 * Change Password
				 * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/ChangePassword
				 */
				case 'password':
					$request = $this->api->call('passwd', array('user' => $args['package']['username'], 'pass' => urlencode($value)));
					// passwd has a different json struct... 
					if ( $request->passwd[0]->status != 1 )
					{
						$errors[] = $this->email_error('Password Change', $request->passwd[0]->statusmsg, $args);
					}
					break;

				/**
				 * Change Domain Name
				 * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/ModifyAccount
				 */
				case 'domain':
					$request = $this->api->call('modifyacct', array('user' => $args['package']['username'], 'domain' => $value));
					if ( $request->result[0]->status != 1 )
					{
						$errors[] = $this->email_error('Domain Change', $request->result[0]->statusmsg, $args);
					}
					break;
				
				/**
				 * Change IP Address
				 * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/SetSiteIp
				 */
				case 'ip':
					$request = $this->api->call('setsiteip', array('user' => $args['package']['username'], 'ip' => $value));
					if ( $request->result[0]->status != 1 )
					{
						$errors[] = $this->email_error('IP Change', $request->result[0]->statusmsg, $args);
					}
					break;
				/** TODO:
				 * Change Package
				 * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/ChangePackage
				 */
				case 'package':
					if (!$this->CheckCpanelPlan($args['package']['name_on_server'], $args)) exit;

					$request = $this->api->call('changepackage', array('user' => $args['package']['username'], 'pkg' => urlencode($args['package']['name_on_server'])));

					if ( $request->result[0]->status != 1 )
					{
						$errors[] = $this->email_error('Plan Change', $request->result[0]->statusmsg, $args);
					}
					else
					{
						// setup or delete the reseller permissions if necessary
						if ( isset($args['package']['is_reseller']) && $args['package']['is_reseller'] == 1 ) {
							if ( !isset($args['changes']['leave_reseller']) ) {
								$this->_addReseller($args);
								$this->_setResellerACLs($args);
							}
						} else {
							// If the old package was a reseller, we need to remove it.
							if ( isset($args['changes']['remove_reseller']) && $args['changes']['remove_reseller'] == 1 )
								$this->_removeReseller($args);
						}
					}
					break;
			}
		}
		
		if ( count($errors) > 0 )
		{
			$this->logger->log(4, "plugin_cpanel::update::error: ".print_r($errors,true));
			throw new Exception ( $errors[0] );
		}
		else
		{
			return;
		}
	}

	function doDelete($args)
	{
		$userPackage = new UserPackage($args['userPackageId']);
		$this->delete($this->buildParams($userPackage));
		return $userPackage->getCustomField("Domain Name") . ' has been deleted.';
	}
	
	/**
	* Removes an account from the cPanel server.
	* @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/TerminateAccount
	* @param <type> $args
	* @return NE_Error
	*/
	function delete($args)
	{
		$this->setup($args);
		$args = $this->updateArgs($args);
		$request = $this->api->call('removeacct', array('user' => $args['package']['username']));

		if ( $request->result[0]->status != 1 )
		{
			$error = $this->email_error ( 'Deletion', $request->result[0]->statusmsg, $args );
		}

		// Rather than returning an error object every time, just return it here.
		// Need to check if an actual error exists to avoid returning an error object on a success message
		if ( isset($error) )
		{
			$this->logger->log(4, "plugin_cpanel::delete::error: ".$error);
			throw new Exception ( $error );
		}
		else
		{
			return;
		}
	}

	function doSuspend($args)
	{
		$userPackage = new UserPackage($args['userPackageId']);
		$this->suspend($this->buildParams($userPackage));
		return $userPackage->getCustomField("Domain Name") . ' has been suspended.';
	}
	
	/**
	* Suspends an account.
	* @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/SuspendAccount
	* @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/SuspendReseller
	* @param <type> $args
	* @return NE_Error
	*/
	function suspend($args)
	{
		$this->setup($args);
		$args = $this->updateArgs($args);
		$action = ( isset($args['package']['is_reseller']) ) ? 'suspendreseller' : 'suspendacct';
		$request = $this->api->call($action, array('user' => $args['package']['username']));

		if ( $request->result[0]->status != 1 )
		{
			$error = $this->email_error( 'Suspension', $request->result[0]->statusmsg, $args );
		}

		// Rather than returning an error object every time, just return it here.
		// Need to check if an actual error exists to avoid returning an error object on a success message
		if ( isset($error) )
		{
			$this->logger->log(4, "plugin_cpanel::suspend::error: ".$error);
			throw new Exception ( $error );
		}
		return;
	}

	function doUnSuspend($args)
	{
		$userPackage = new UserPackage($args['userPackageId']);
		$this->unsuspend($this->buildParams($userPackage));
		return $userPackage->getCustomField("Domain Name") . ' has been unsuspended.';
	}
	
	/**
	* Unsuspends an account
	* @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/UnsuspendAcount
	* @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/UnsuspendReseller
	* @return NE_Error
	*/
	function unsuspend($args)
	{
		$this->setup($args);
		$args = $this->updateArgs($args);
		$action = ( isset($args['package']['is_reseller']) ) ? 'unsuspendreseller' : 'unsuspendacct';
		$request = $this->api->call($action, array('user' => $args['package']['username']));

		if ( $request->result[0]->status != 1 )
		{
			$error = $this->email_error ( 'Unsuspension', $request->result[0]->statusmsg, $args );
		}

		// Rather than returning an error object every time, just return it here.
		// Need to check if an actual error exists to avoid returning an error object on a success message
		if ( isset($error) )
		{
			$this->logger->log(4, "plugin_cpanel::unsuspend::error: ".$error);
			throw new Exception ( $error );
		}

		return;
	}

    /**
     * Tests that the account credentials are working.
     * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/DisplaycPanelWHMVersion
     * @param <type> $args
     * @return NE_Error
     */
    function testLogin($args)
    {
	    $this->setup($args);
	    $version = $this->api->version();

	    $this->logger->log(4, 'Cpanel Version: '.$version);

	    if ( strlen(trim($version)) == 0 )
	    {
		    return new Exception("Connection to server failed.");
	    }
    }

	/**
	 * Setup Reseller Account Creatin Limits
	 * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/SetResellersACLList
	 * @param <type> $args
	 */
	function _setResellerACLs($args)
	{
		$this->setup($args);
		$args = $this->updateArgs($args);
		// TODO: Verify that these are correct ACLs and what they do.
		$resourceLimits = array('acl-rslimit-disk', 'acl-rsolimit-disk', 'acl-rslimit-bw', 'acl-rsolimit-bw', 'acl-domain-quota');

                $acls = array();
                if ( isset($args['package']['acl']['acl-name'])&& $args['package']['acl']['acl-name'] != '' ) {
                    $this->logger->log(2, 'Using ACL Name: ' . $args['package']['acl']['acl-name']);
                    $acls['acllist'] = $args['package']['acl']['acl-name'];
                } else {
                    foreach ( $args['package']['acl'] as $key => $value ) {
                        if ( mb_substr ($key, 0, 4) == 'acl-' ) {
                            if ( in_array($key, $resourceLimits) ) {
                                $key = mb_substr($key, 4);
                            }
                            $acls[$key] = $value;
                        }
                    }

                    if ( (isset($args['package']['acl']['acl-rslimit-disk']) && $args['package']['acl']['acl-rslimit-disk']) || (isset($args['package']['acl']['acl-rslimit-bw']) && $args['package']['acl']['acl-rslimit-bw'])) {
                        $acls['resreslimit'] = 1;
                    }

                    // Only send ACLs that are set to 1.  Even if set to 0, cPanel still enables them.
                    foreach ( $acls as $key => $value ) {
                        if ( $value != '1' ) {
                            unset($acls[$key]);
                        }
                        // This key is for domain quota, which is sent as a seperate API call (setresellerlimits).
                        if ( $key == 'acl-domain-quota'  ) {
                            unset($acls[$key]);
                        }
                    }
                }
                
		$request = $this->api->call('setacls', array_merge(array('reseller' => $args['package']['username']), $acls));

		if ( $request->result[0]->status != 1 ) {
                    $error = $request->result[0]->statusmsg . ' setacls';
                    $this->email_error ( 'Setup Reseller', $error, $args );
		}

                $tmpArgs = array();
                
		// Setup domain quota for the reseller
		if ( (isset($args['package']['acl']['acl-domain-quota']) && $args['package']['acl']['acl-domain-quota'] > 0 ) )
		{
			$tmpArgs['enable_account_limit'] = 1;
                        $tmpArgs['account_limit'] = $args['package']['acl']['acl-domain-quota']; 
		}
                
                if ( (isset($args['package']['acl']['acl-rslimit-disk']) && $args['package']['acl']['acl-rslimit-disk']) || (isset($args['package']['acl']['acl-rslimit-bw']) && $args['package']['acl']['acl-rslimit-bw']))
                {
                    $tmpArgs['enable_resource_limits'] = 1; 
                    $tmpArgs['bandwidth_limit'] = $args['package']['acl']['acl-rslimit-bw'];
                    $tmpArgs['diskspace_limit'] = $args['package']['acl']['acl-rslimit-disk'];
                                 
                    if ( (isset($args['package']['acl']['acl-rsolimit-disk']) && $args['package']['acl']['acl-rsolimit-disk'] == 1) || isset($args['package']['acl']['rsolimit-bw']) && $args['package']['acl']['rsolimit-bw']  )
                    {
                        $tmpArgs['enable_overselling'] = 1;
                        $tmpArgs['enable_overselling_bandwidth'] = $args['package']['acl']['acl-rsolimit-bw'];
                        $tmpArgs['enable_overselling_diskspace'] = $args['package']['acl']['acl-rsolimit-disk'];
                    }
                }
                
                if ( count($tmpArgs) > 0 ) {
                    $request = $this->api->call('setresellerlimits', array_merge(array('user' => $args['package']['username']), $tmpArgs));
                    if ( $request->result[0]->status != 1 )
                    {
                        $error = $request->result[0]->statusmsg . ' setupresellerlimits';
                        $this->email_error ( 'Setup Reseller Limits', $error, $args );
                    }
                }

		// Rather than returning an error object every time, just return it here.
		// Need to check if an actual error exists to avoid returning an error object on a success message
		if ( isset($error) )
		{
			$this->logger->log(4, "plugin_cpanel::setupreselleracls::error: ".$error);
			throw new Exception ( $error );
		}
	}

	/**
	 * Add reseller privileges to an account.
	 * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/AddResellerPrivileges
	  * @param <type> $args
	*/
	function _addReseller($args)
	{
		$this->setup($args);
		$args = $this->updateArgs($args);
		$request = $this->api->call('setupreseller', array('user' => $args['package']['username'], 'makeowner' => '1'));

		if ( $request->result[0]->status != 1 )
		{
			$error = $this->email_error ( 'Setup Reseller', $request->result[0]->statusmsg, $args );
		}

		// Rather than returning an error object every time, just return it here.
		// Need to check if an actual error exists to avoid returning an error object on a success message
		if ( isset($error) )
		{
			$this->logger->log(4, "plugin_cpanel::setupreseller::error: ".$error);
			throw new Exception ( $error );
		}
	}

	/**
	 * Remove reseller privileges from an account.
	 * @link http://docs.cpanel.net/twiki/bin/view/AllDocumentation/AutomationIntegration/RemoveResellerPrivileges
	 * @param <type> $args
	 */
	function _removeReseller($args)
	{
		$this->setup($args);
		$request = $this->api->call('unsetupreseller', array('user' => $args['package']['username'], 'makeowner' => 1));

		if ( $request->result[0]->status != 1 )
		{
			$error = $this->email_error ( 'Unsetup Reseller', $request->result[0]->statusmsg, $args );
		}

		// Rather than returning an error object every time, just return it here.
		// Need to check if an actual error exists to avoid returning an error object on a success message
		if ( isset($error) )
		{
			$this->logger->log(4, "plugin_cpanel::unsetupreseller::error: ".$error);
			throw new Exception ( $error );
		}
	}

	/**
	* Updates any $args as needbe for the cPanel Plugin (usernames must be lowercase, etc)
	*
	* @param array $args
	*
	*/
	private function updateArgs($args)
	{
		$args['package']['username'] = trim(strtolower($args['package']['username']));
		if ( isset($args['changes']['username']) )
			$args['changes']['username'] = trim(strtolower($args['changes']['username']));
			
		return $args;
	}
	
	function getAvailableActions($userPackage)
	{
		$args = $this->buildParams($userPackage);
		$this->setup($args);
                $args = $this->updateArgs($args);
		$actions = array();	
		try {
			$request = $this->api->call('accountsummary', array('user' => $args['package']['username']));
			$actions[] = 'Delete';
			if ( $request->acct[0]->suspended == 1 ) {
				$actions[] = 'UnSuspend';
			} else {
				$actions[] = 'Suspend';
			}
		} catch (Exception $e) {
			$actions[] = 'Create';
		}		
		return $actions;
	}
}
?>