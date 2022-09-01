## XSS Vulnerability Reports

| Application               | ID    | Source                                                       | Sink                                                         | Sanitizer            | RIPS result | phpSAFE result | Phpjoern result | PAT result | our report                                                   |
| ------------------------- | ----- | ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------- | ----------- | -------------- | --------------- | ---------- | ------------------------------------------------------------ |
| myBB                      | vul1  | $_SERVER['PHP_SELF'] (mybb/inc/functions.php:5209)           | echo $bburl (myBB/install/index.php:1964)                    | htmlspecialchars_uni | FP          | FP             | FP              | TN         |                                                              |      |
| myBB                      | vul2  | getenv('REQUEST_URI')(mybb/admin/inc/class_page.php:221)     | echo $debuglink (myBB/admin/inc/class_page.php:229)          | htmlspecialchars_uni | FP          | FP             | FP              | TN         |                                                              |
| myBB                      | vul3  | $_SERVER['QUERY_STRING'] (myBB/admin/index.php:422)          | echo $query_string (myBB/admin/index.php:510)                | htmlspecialchars_uni | FP          | FP             | FP              | TN         |                                                              |      |
| myBB                      | vul4  | $_SERVER['QUERY_STRING'] (myBB/admin/index.php:551)          | echo $query_string (myBB/admin/index.php:575)                | htmlspecialchars_uni | FP          | FP             | FP              | TN         |                                                              |      |
| myBB                      | vul5  | $mybb->input['page'] (myBB/modules/user/group_promotions.php: 718) | echo $mybb->input['page'] (myBB/modules/user/group_promotions.php:718) |                      | TN          | TN             | TN              | FP         |                                                              |      |
| phpBB                     | vul1  | $argv[2] (phpBB/develop/create_search_index.php:41)          | printf("%d", \$post_counter+$batch_size) (phpBB/develop_create_search_index.php:75) |                      | FP          | FP             | FP              | FP         |                                                              |      |
| phpBB                     | vul2  | $argv[1] (phpBB/develop/search_fill.php:99)                  | echo $_SERVER['PHP_SELF'] (phpBB/develop/search_fill.php:99) |                      | TP          | TP             | TP              | TP         |                                                              |      |
| mantisBT                  | vul1  | gpc_get_string('view_type', $t_filter['_view_type']) (manage_filter_edit_page.php:78) | echo $t_filter['_view_type']; (manage_filter_edit_page.php:93) |                      | FN          | FN             | FN              | TP         |                                                              |      |
| mantisBT                  | vul2  | gpc_get('type', 'bug') (move_attachments_page.php:41)        | echo $t_disk_count (move_attachements_page.php:163)          |                      | FN          | FN             | FN              | FP         |                                                              |
| mantisBT                  | vul3  | gpc_get_string('filter_target') (return_dynamic_filter.php:88) | echo $content (return_dynamic_filter.php:88)                 |                      | FN          | FN             | FN              | FP         |                                                              |
| mantisBT                  | vul4  | gpc_get_string() (browser_search_plugin.php:37)              | echo $t_shortname (browser_search_plugin.php:59)             |                      | FN          | FN             | FN              | FP         |                                                              |
| mantisBT                  | vul5  | gpc_get_string('view_type', $filter['_view_type']) (view_filter_page.php: 92) | echo $t_filter['_view_type'] (view_filters_page:104)         |                      | FN          | FN             | FN              | TP         |                                                              |      |
| mantisBT                  | Vul6  | gpc_get('admin_user_name') (install.php:216)                 | echo $f_admin_username (install.php:1522)                    |                      | FN          | FN             | FN              | TP         | [mantibt-0027444](https://mantisbt.org/bugs/view.php?id=27444) |
| mantisBT                  | vul7  | gpc_get_string('action', '') (bug_actiongroup_page.php:62)   | echo $t_form_name (bug_actiongroup_page.php:247)             |                      | FN          | FN             | FN              | FP         |                                                              |
| mantisBT                  | vul8  | gpc_get_string('redirect', 'account_prof_menu_page.php') (account_prof_edit_page.php:100) | echo $f_redirect_page (account_prof_edit_page.php:63)        |                      | FN          | FN             | FN              | TP         | [mantibt-0027853](https://mantisbt.org/bugs/view.php?id=27853) |
| mantisBT                  | vul9  | db_error_msg() (upgrade_unattended.php:85)                   | echo (upgrade_unattnded.php:85)                              |                      | FN          | FN             | FN              | FP         |                                                              |
| impressCMS                | vul1  | echo $_GET['fct'] (templates_c/default-iTheme_admin.html.php:242) | echo $_GET['fct'] (templates_c/default-iTheme_admin.html.php:242) |                      | TP          | TP             | TP              | TP         |                                                              |      |
| impressCMS                | vul2  | echo $_SERVER['PHP_SELF'] (settings_trust_path.php:64)       | echo $_SERVER['PHP_SELF'] (settings_trust_path.php:64)       |                      | TP          | TP             | TP              | TP         |                                                              |      |
| impressCMS                | vul3  | $_GET['command'] (connector.php:48)                          | echo $command (basexml.php:53)                               |                      | FP          | FP             | FP              | TN         |                                                              |      |
| impressCMS                | vul4  | $_POST['com\_title'] (comment_post.php:139)                  | echo $com_title(comment_post.php:152)                        |                      | FP          | FP             | TN              | TN         |                                                              |      |
| impressCMS                | vul5  | $_POST['queryString'] (suggest.php:14)                       | echo $result['url'] (suggest.php:35)                         |                      | FP          | FP             | FP              | TN         |                                                              |      |
| impressCMS                | vul6  | $_POST['query'] (findusers.php:297)                          | echo $total (findusers.php:393)                              |                      | FP          | FP             | TN              | TN         |                                                              |      |
| impressCMS                | vul7  | $_POST['login_name'] (register:58)                           | echo $stop (register:120)                                    |                      | FP          | FP             | FP              | TN         |                                                              |      |
| impressCMS                | vul8  | $_POST['textinputs']; (fck_spellerpages/spellchecker.php:17) | echo $key; (fck_spellerpages/spellchecker.php:27)            |                      | TP          | TP             | TP              | TP         |                                                              |      |
| impressCMS                | vul9  | $_POST['query'] (xoopsimagebrowser.php:372)                  | \$icmsTpl->assign('query', $query) (xoopsimagebrowser.php:275) |                      | FN          | FN             | FN              | TP         | [hakcerone-1165452](https://hackerone.com/bugs?subject=user&report_id=1165452&view=open&substates%5B%5D=new&substates%5B%5D=needs-more-info&substates%5B%5D=pending-program-review&substates%5B%5D=triaged&substates%5B%5D=pre-submission&substates%5B%5D=retesting&reported_to_team=&text_query=&program_states%5B%5D=2&program_states%5B%5D=3&program_states%5B%5D=4&program_states%5B%5D=5&sort_type=latest_activity&sort_direction=descending&limit=25&page=1) |      |
| impressCMS                | vul10  | $_GET['\$extra\_param'] (comment\_view.php:208)                  | \$xoopsTpl->assign(\$link_extra) (comment\_view.php:275) |                      | FN          | FN             | FN              | FP         ||
| impressCMS                | vul11  | $_GET['\$extra\_param'] (comment\_view.php:113)                  | \$xoopsTpl->assign(\$link_extra) (comment\_view.php:123) |                      | FN          | FN             | FN              | FP         ||
| collabtive                | vul1  | $_GET (manageress.php:8)                                     | echo $user (manageress.php:90)                               | getarrayval          | FP          | FP             | FP              | TN         |                                                              |      |
| collabtive                | vul2  | $_GET (manageress.php:8)                                     | echo $user (manageress.php:141)                              | getarrayval          | FP          | FP             | FP              | TN         |                                                              |      |
| collabtive                | vul3  | $_GET (manageress.php:9)                                     | echo $user (manageress.php:205)                              | getarrayval          | FP          | FP             | FP              | TN         |                                                              |      |
| collabtive                | vul4  | $_GET (managetasksoverview.php:42)                           | echo $globalTasks (managetasksoverview.php:86)               | getarrayval          | FP          | FP             | FP              | TN         |                                                              |      |
| collabtive                | vul5  | $_GET (manageajax.php:195)                                   | echo $chk (manageajax.php:200)                               | getarrayval          | FP          | FP             | FP              | TN         |                                                              |      |
| collabtive                | vul6  | $_GET (managesearch.php:5)                                   | echo $res (managesearch.php:106)                             | getarrayval          | FP          | FP             | FP              | TN         |                                                              |      |
| collabtive                | vul7  | $_GET (managesearch.php:5)                                   | echo $res (managesearch.php:114)                             | getarrayval          | FP          | FP             | FP              | TN         |                                                              |      |
| collabtive                | vul8  | \$_GET (managesearch.php:5)                                   | echo $res (managesearch.php:123)                             | getarrayval          | FP          | FP             | FP              | TN         |                                                              |
| collabtive                | vul9  | $_GET['file'] (managefile.php)                               | echo $file (managefile.php:303)                              | getarrayval          | TP          | TP             | TP              | TP         |                                                              |      |
| accordions                | vul1  | $_REQUEST['tab'] (settings.php:5)                            | echo $current_tab (settings.php: 54)                         |                      | TP          | TP             | TP              | TP         | [CVE-2021-24283](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24283) |      |
| accordions                | vul2  | $_SERVER['REQUEST_URI'] (settings.php:52)                    | echo str_replace('%7E', '~', $_SERVER['REQUEST_URI']) (settings.php:52) |                      | TP          | TP             | TP              | TP         |                                                              |      |
| accordions                | vul3  | $_GET['active_index'] (tabs-hook.php:461)                    | echo $accordion_id (tabs-hook.php:461)                       | sanitize_text_field  | FP          | TN             | FP              | TN         |                                                              |      |
| accordions                | vul4  | $_GET['active_index'] (tabs-hook.php:461)                    | echo $accordion_indexes (tabs-hook.php:468)                  | sanitize_text_field  | FP          | TN             | FP              | TN         |                                                              |      |
| accordions                | vul5  | $_GET['id'] (tab-hook.php:529)                               | echo $active_tab (tab-hook.php:549)                          | sanitize_text_field  | FP          | TN             | FP              | TN         |                                                              |      |
| accordions                | vul6  | $_GET['active_index'] (accordion-hook.php:410)               | echo $accordion_id (accordion-hook.php:424)                  | sanitize_text_field  | FP          | TN             | FP              | TN         |                                                              |      |
| accordions                | vul7  | $_GET['active_index'] (accordion-hook.php:410)               | echo $active_index (accordion-hook.php:427)                  | sanitize_text_field  | FP          | TN             | FP              | TN         |                                                              |      |
| advanced-booking-calendar | vul1  | echo abc_booking_edittextcustomization($_POST)(backend/settings.php:167) | echo abc_booking_edittextcustomization($_POST)(backend/settings.php:167) | sanitize_text_field  | FP          | TN             | FP              | TN       |                                                              |      |
| advanced-booking-calendar | vul2  | $_POST['state'] (backend/bookings.php:111)                   | echo abc_booking_getbookingcontent($state) (backend/bookings.php:113) | sanitize_text_field  | FP          | TN             | FP              | TN         |                                                              |      |
| advanced-booking-calendar | vul3  | $_POST['search'] (backend/bookings.php:1575)                 | echo $accordion (backend/bookings.php:1668)                  | sanitize_text_field  | FP          | TN             | FP              | TN         |                                                              |      |
| advanced-booking-calendar | vul4  | $_GET['message'] (backend/settings.php:609)                  | echo urldecode($_GET['message']) (backend/settings.php:609)  |                      | TP          | TP             | TP              | TP         | [CVE-2021-24232](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24232) |      |
| advanced-booking-calendar | vul5  | $_GET['callId'] (backend/settings.php:426)                   | echo $output (backend/settings.php:1003)                     |                      | FN          | TP             | TP              | TP         | [CVE-2021-24225](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24225) |      |
| advanced-booking-calendar | vul6  | $_POST (frontend/calendaroverview.php:169)                   | echo abc_booking_getCalOverview($_POST) (frontend/calendaroverview.php:169) |                      | TN          | TN             | FP              | TN         |                                                              |      |
| pie-register              | vul1  | $_GET['initaion_code'] (pie_register:2052)                   | echo $inv_code (pie_register.php:2071)                       |                      | TP          | TP             | TP              | TP         | [CVE-2021-24239](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24239) |      |
| pie-register              | vul2  | $_POST['id'] (forgot_password.php:2261)                      | echo $meta (forgot_password.php:2263)                        |                      | TP          | TP             | TP              | TP         |                                                              |      |
| pie-register              | vul3  | $_REQUEST['orderby'] (inviation_code_pagination.php:75)      | echo esc_attr($_REQUEST['orderby']) (invitation_code_pagination.php:75) | esc_attr             | FP          | TN             | FP              | TN         |                                                              |      |
| pie-register              | vul4  | $_REQUEST['order'] (inviation_code_pagination.php:77)        | echo esc_attr($_REQUEST['orderby']) (invitation_code_pagination.php:77) | esc_attr             | FP          | TN             | FP              | TN         |                                                              |      |
| pie-register              | vul5  | $_REQUEST['order'] (inviation_code_pagination.php:79)        | echo esc_attr($_REQUEST['page']) (invitation_code_pagination.php: 79) | esc_attr             | FP          | TN             | FP              | TN         |                                                              |      |
| pie-register              | vul6  | $_GET['login'] (get_password.php:43)                         | echo esc_attr($_GET['login']) (get_password.php:43)          | esc_attr             | FP          | TN             | FP              | TN         |                                                              |      |
| pie-register              | vul7  | $_POST['notice'] (PieRegPaymentGateway.php:21)               | echo $_POST['notice'] (PieRegPaymentGateway.php:21)          |                      | TP          | TP             | TP              | TP         |                                                              |      |
| pie-register              | vul8  | $_POST['notice'] (PieRegBulkEmail.php:11)                    | echo $_POST['notice'] (PieRegBulkEmail.php:11)               | esc_attr             | FP          | TN             | FP              | TN         |                                                              |      |
| pie-register              | vul9  | $_POST['error'] (PieRegBulkEmail.php:13)                     | echo $_POST['error'] (PieRegBulkEmail.php:13)                | esc_attr             | FP          | TN             | FP              | TN         |                                                              |      |
| pie-register              | vul10 | $_POST['warning'] (PieRegBulkEmail,php:16)                   | echo $_POST['warning'] (PieRegBulkEmail.php:16)              | esc_attr             | FP          | TN             | FP              | TN         |                                                              |      |
| pie-register              | vul11 | $_POST['notice'] (PieRegExportUsers.php:11)                  | echo $_POST['notice'] (PieRegExportUsers.php:11)             | esc_attr             | FP          | TN             | FP              | TN         |                                                              |      |
| pie-register              | vul12 | $_POST['error'] (PieRegExportUsers.php:13)                   | echo $_POST['error'] (PieRegExportUsers.php:13)              | esc_attr             | FP          | TN             | FP              | TN         |                                                              |      |
| pie-register              | vul13 | $_POST['warning'] (PieRegExportUsers.php:16)                 | echo $_POST['warning'] (PieRegExportUsers.php:16)            | esc_attr             | FP          | TN             | FP              | TN         |                                                              |      |
| player                    | vul1  | $_GET['id'] (Spider_Video_Player_function.html.php:20)       | echo $id (Spider_Video_Player_function.html.php:307)         |                      | FN          | FN             | TP              | TP         |                                                              |      |
| player                    | vul2  | $_GET['trackID'] (function_for_xml_and_ajax:1230)            | echo $priority (player.php:759)                              |                      | FP          | FP             | TN              | TN         |                                                              |      |
| player                    | vul3  | $_GET['trackID'] (function_for_xml_and_ajax:1230)            | echo $priority (player.php:759)                              |                      | FP          | FP             | TN              | TN         |                                                              |      |
| player                    | vul4  | $_GET['AlbumId'] (player.php:228)                            | echo $AlbumId (player.php:1685)                              | esc_html             | FP          | TN             | FP              | TN         |                                                              |      |
| player                    | vul5  | $_GET['AlbumId'] (player.php:1883)                           | echo $AlbumId (player.php:3645)                              | esc_html             | FP          | TN             | FP              | TN         |                                                              |      |
| player                    | vul6  | $_GET['TrackId'] (player.php:1887)                           | echo $AlbumId (player.php:3645)                              | esc_html             | FP          | TN             | FP              | TN         |                                                              |      |
| player                    | vul7  | $theme->appHeight + 25 .'px'; (player.php:225)               | echo $share_top (player.php:2394)                            |                      | TN          | FP             | FP              | TN         |                                                              |      |
| player                    | vul8  | $theme->appHeight + 25 .'px'; (player.php:225)               | echo $share_top (player.php:2606)                            |                      | TN          | FP             | FP              | TN         |                                                              |      |
| sport                     | vul1  | $_REQUEST['match_day'] (class-sp-admin-cpt-event.php:293)    | echo $seleected (class-sp-admin-cpt-event.php:294)           |                      | TP          | TP             | TP              | TP         | [CVE-2021-24578](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24578) |      |
| sport                     | vul2  | $_REQUEST (class-sp-evnet-performance-importer.php:170)      | echo $event (class-sp-evnet-performance-importer.php:184)    |                      | TP          | TP             | TP              | TP         |                                                              |      |
| sport                     | vul3  | $_REQUEST (class-sp-evnet-performance-importer.php:171)      | echo $teams (class-sp-evnet-performance-importer.php:185)    |                      | TP          | TP             | TP              | TP         |                                                              |      |
| sport                     | vul4  | $_REQUEST (class-sp-evnet-performance-importer.php:172)      | echo $index (class-sp-evnet-performance-importer.php:186)    |                      | TP          | TP             | TP              | TP         |                                                              |      |
| sport                     | vul5  | $_REQUEST (class-sp-evnet-performance-importer.php:170)      | echo get_post_permalink($event); (class-sp-evnet-performance-importer.php:181) |                      | FP          | FP             | FP              | FP         |                                                              |      |
| sport                     | vul6  | $_REQUEST (class-sp-evnet-performance-importer.php:170)      | echo get_the_title($event);  (class-sp-evnet-performance-importer.php:182) |                      | FP          | FP             | FP              | FP         |                                                              |      |
| sport                     | vul7  | $_GET['tab'] (sportspress-tutorials.php:148)                 | echo $section (sportspress-tutorials.php:160)                |                      | FP          | FP             | TN              | TN         |                                                              |      |
| sport                     | vul8  | $_GET['tab'] (sportspress-tutorials.php:149)                 | echo $label (sportspress-tutorials.php:168)                  |                      | FP          | FP             | TN              | TN         |                                                              |      |
| sport                     | vul9  | $_GET['tab'] (sportspress-tutorials.php:150)                 | echo $url (sportspress-tutorials.php:176)                    |                      | FP          | FP             | TN              | TN         |                                                              |      |
| sport                     | vul10 | $_GET['taxonomy'] (sportpress-overview.php:351)              | echo (sportpress-overview.php:358)                           |                      | TN          | TN             | FP              | FP         |                                                              |
| sport                     | vul11 | $_POST['first_name'] (sportspress-user-registration.php:100) | echo $first_name  (sportspress-user-registration.php:100)    | esc_attr             | TN          | TN             | FP              | TN         |                                                              |      |
| sport                     | vul12 | $_POST['last_name'] (sportspress-user-registration.php:101)  | echo $last_name (sportspress-user-registration.php:110)      | esc_attr             | TN          | TN             | FP              | TN         |                                                              |      |
| sport                     | vul13 | $_GET['type'] (sportspress-overview.php:275)                 | echo $post_type (sportspress-overview.php:283)               | esc_url              | TN          | TN             | FP              | TN         |                                                              |      |
| sport                     | vul14 | $_GET['taxonomy'] (sportspress-overview.php:351)             | echo $post_type (sportspress-overview.php:358)               | esc_url              | TN          | TN             | FP              | TN         |                                                              |      |
|                           |       |                                                              |                                                              |                      |             |                |                 |            |                                                              |
