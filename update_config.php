<?php
	include("expired_check.php");
	include("encoding_json.php");
	// if(!isset($key_value))
	//  {
	// 	$key_value = $_POST["key_value"];
	//  }

	// $data = array();
	// $meta["rc"] = "ok";

	$ret = 0;
	if(!isset($key_node))
	{
	 	$key_node = $_POST["key_node"];
    }
    if(!isset($key_value))
	{
	 	$key_value = $_POST["key_value"];
	 	//data[0]["key_value"] = $key_value;
	}
    if($key_node == "country_code")
    {
    	$ret = ext_sys_manage("set_wireless_global_country_code",$key_value);
    }
    else if($key_node == "global_auto_optimize")
    {
    	$ret = ext_sys_manage("set_wireless_global_auto_optim_policy",$key_value);
    }
    else if($key_node == "version_update")
    {
    	$ret = ext_sys_manage("set_afi_version_update_value",$key_value);
    }
    else if($key_node == "network_adaption")
    {	
    	$ret = ext_sys_manage("set_afi_net_adaption_value",(int)$key_value);
    }
    else if($key_node == "access_control")
    {
   		$ret = ext_sys_manage("set_afi_access_control_value",(int)$key_value); 	
    }
    else if($key_node == "user_policy_auto_optim")
    {
    	$ret = ext_sys_manage("set_user_policy_auto_optim_policy",$key_value);
    }
    else
    {
    	//do nothing
    	//$meta["msg"] = "api.err.update_config_failed";
    }

	//$result = array("data"=>$data, "meta"=>$meta);
	echo $key_value.$key_node.$ret;;//json_encode($result);
?>