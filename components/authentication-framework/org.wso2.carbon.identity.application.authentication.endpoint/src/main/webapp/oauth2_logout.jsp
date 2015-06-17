<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.Constants" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <%String sessionDataKey=request.getParameter("sessionDataKey");
        String url= Constants.CHECK_SESSION_ENDPOINT;
    %>
    <script type="text/javascript">
        /**
         * After user approve to logout the server, this method post sessionDataKey value to the servlet
         */
        function ok() {
            var sessionDataKey = '<%=sessionDataKey%>';

            alert(sessionDataKey);
            $.ajax({
                url: '<%=url%>',
                success: function (data) {
                    $.ajax({
                        url: "logout",
                        data : { sessionDataKey : sessionDataKey,type : 'oidc',commonAuthLogout:true},
                        type: "POST",
                        async: false
                    });
                }
            });
        }


        /**
         * If the user cancels the logout,this method executes.
         */
        function cancel() {
            window.close();
        }
    </script>
    <meta charset="utf-8">
    <title>WSO2 Identity Server OAuth2.0 Consent</title>
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="">
    <meta name="author" content="">

    <!-- Le styles -->
    <link href="assets/css/bootstrap.min.css" rel="stylesheet">
    <link href="css/localstyles.css" rel="stylesheet">
    <!--[if lt IE 8]>
    <link href="css/localstyles-ie7.css" rel="stylesheet">
    <![endif]-->

    <!-- Le HTML5 shim, for IE6-8 support of HTML5 elements -->
    <!--[if lt IE 9]>
    <script src="assets/js/html5.js"></script>
    <![endif]-->
    <script src="assets/js/jquery-1.7.1.min.js"></script>
    <script src="js/scripts.js"></script>

</head>
<body>

<div class="header-back">
    <div class="container">
        <div class="row">
            <div class="span4 offset3">
                <a class="logo"> </a>
            </div>
        </div>
    </div>
</div>
<div class="container main-login-container" style="margin-top:10px;">
    <div class="row">
        <div class="span12 content-section">
            <h3 style="text-align:left;margin-bottom:10px;">Do You really want to logout of Identity Server?</h3>
            <button id="ok" class="btn btn-primary btn-large" onclick="ok()">OK</button>
            <button id="cancel" class="btn btn-primary btn-large" onclick="cancel()">Cancel</button>
        </div>
    </div>
</div>
</body>

</html>

