<#
	IDP Initiated SSO from Windows Machine
	Matches the Relying Party name in ADFS
	Requires Relying Party ENDPOINTS to be setup with the following-

	INDEX 0 https://login.{cloud}.net:443/sfc_sso "NOT DEFAULT"
	INDEX 1 https://login.{cloud}.net:443/sso_upd/{company_id_number} "DEFAULT"

	In Relying Party Identifiers, add a "shortname" to the Identifier - e.g. ZS2 to allow it to be called easier

	Script will run silentyly in the background - triggering an Internet Explorer window to perform the IDP SSO, and then post SAML data to cloud
	This will have the effect of periodically updating the users SAML data (Groups, etc) without any user interaction

#>
$ie = new-object -ComObject "InternetExplorer.Application";
$requestUri = "https://adfs.welshgeek.net/adfs/ls/idpinitiatedsignon?logintoRp=ZS2";
$ie.visible = $true;
$ie.silent = $true;
$ie.navigate($requestUri);
while($ie.Busy) { Start-Sleep -Milliseconds 1000; }
$ie.quit
