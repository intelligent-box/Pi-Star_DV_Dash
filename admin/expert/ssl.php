<?php
/**
 * Expert SSL manager page.
 *
 * Provides a toggle that turns the instance's SSL support on or off,
 * generates the certificate through the same self-signed flow as the
 * legacy `pistar-sslgenerate` script, and installs an interval-based
 * renewal check so the cert is rotated before the one-year expiry window.
 */
require_once($_SERVER['DOCUMENT_ROOT'].'/config/security_headers.php');
require_once($_SERVER['DOCUMENT_ROOT'].'/config/csrf.php');
require_once($_SERVER['DOCUMENT_ROOT'].'/config/banner_warnings.inc');
setSecurityHeaders();

// CSRF protection — must run BEFORE any output.
csrf_verify();

// Layer 2 of the default-password protection — see config/banner_warnings.inc.
// MUST run BEFORE any output so header('Location: ...') works.
pistar_warnings_enforce_redirect();

// Load the language support.
require_once('../config/language.php');
// Load the Pi-Star Release file.
$pistarReleaseConfig = '/etc/pistar-release';
$configPistarRelease = array();
$configPistarRelease = parse_ini_file($pistarReleaseConfig, true);
// Load the Version Info.
require_once('../config/version.php');

function pistar_ssl_state_file_path()
{
    return '/etc/pistar-ssl';
}

function pistar_ssl_read_state()
{
    $state = array(
        'enabled' => false,
        'certificate_exists' => file_exists('/etc/ssl/certs/pi-star.crt'),
        'renewal_installed' => file_exists('/etc/cron.daily/pistar-ssl-renew'),
        'renewal_months' => 11,
    );

    $stateFile = pistar_ssl_state_file_path();
    if (file_exists($stateFile)) {
        $parsed = @parse_ini_file($stateFile, true);
        if (is_array($parsed) && isset($parsed['SSL']['enabled'])) {
            $state['enabled'] = ((int)$parsed['SSL']['enabled'] === 1);
        }
        if (is_array($parsed) && isset($parsed['SSL']['renewal_months'])) {
            $months = (int)$parsed['SSL']['renewal_months'];
            if ($months >= 1 && $months <= 11) {
                $state['renewal_months'] = $months;
            }
        }
    }

    return $state;
}

function pistar_ssl_write_state($enabled, $renewalMonths)
{
    $stateFile = pistar_ssl_state_file_path();
    $tmp = tempnam('/tmp', 'pistar-ssl-state-');
    if ($tmp === false) {
        return array('Could not stage the SSL state file.');
    }

    $renewalMonths = (int)$renewalMonths;
    if ($renewalMonths < 1 || $renewalMonths > 11) {
        $renewalMonths = 11;
    }

    $content = "[SSL]\nenabled=" . ($enabled ? '1' : '0') . "\nrenewal_months=" . $renewalMonths . "\n";
    if (file_put_contents($tmp, $content) === false) {
        unlink($tmp);
        return array('Could not write the SSL state file to the temporary staging area.');
    }

    exec('sudo mount -o remount,rw /');
    $installRc = 0;
    exec('sudo install -m 644 -o root -g root ' . escapeshellarg($tmp) . ' ' . escapeshellarg($stateFile), $out, $installRc);
    exec('sudo mount -o remount,ro /');
    unlink($tmp);

    if ($installRc !== 0) {
        return array('Could not install the SSL state file into /etc.');
    }

    return array();
}

function pistar_ssl_ensure_certificate()
{
    $certPath = '/etc/ssl/certs/pi-star.crt';
    $keyPath = '/etc/ssl/private/pi-star.key';
    $script = '/usr/local/sbin/pistar-sslgenerate';

    if (file_exists($script)) {
        exec('sudo ' . escapeshellarg($script) . ' > /dev/null 2>&1 &');
        return;
    }

    if (file_exists($certPath)) {
        return;
    }

    exec('sudo mount -o remount,rw /');
    exec('sudo mkdir -p /etc/ssl/certs /etc/ssl/private > /dev/null 2>&1');
    exec('sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 '
        . '-keyout ' . escapeshellarg($keyPath)
        . ' -out ' . escapeshellarg($certPath)
        . ' -subj "/C=GB/ST=London/L=London/O=Team Pi-Star/OU=IT Department/CN=pi-star/subjectAltName=DNS:pi-star,DNS:pi-star.local,DNS:pi-star*,DNS:pi-star*.local" > /dev/null 2>&1');
    exec('sudo mount -o remount,ro /');
}

function pistar_ssl_force_renew()
{
    $script = '/usr/local/sbin/pistar-sslgenerate';

    if (file_exists($script)) {
        exec('sudo ' . escapeshellarg($script) . ' force > /dev/null 2>&1 &');
        return;
    }

    $certPath = '/etc/ssl/certs/pi-star.crt';
    $keyPath = '/etc/ssl/private/pi-star.key';
    exec('sudo rm -f ' . escapeshellarg($certPath) . ' ' . escapeshellarg($keyPath) . ' > /dev/null 2>&1');
    pistar_ssl_ensure_certificate();
}

function pistar_ssl_ensure_renewal_schedule()
{
    $stateFile = pistar_ssl_state_file_path();
    $renewScript = '/etc/cron.daily/pistar-ssl-renew';
    $scriptBody = "#!/bin/sh\n"
        . "STATEFILE=\"$stateFile\"\n"
        . "if [ ! -f \"$stateFile\" ]; then\n"
        . "  exit 0\n"
        . "fi\n"
        . "ENABLED=\"$(awk -F= '/^enabled=/{print $2}' \"$stateFile\" | tr -d '\\r')\"\n"
        . "RENEW_MONTHS=\"$(awk -F= '/^renewal_months=/{print $2}' \"$stateFile\" | tr -d '\\r')\"\n"
        . "if [ \"$ENABLED\" != \"1\" ]; then\n"
        . "  exit 0\n"
        . "fi\n"
        . "if [ -z \"$RENEW_MONTHS\" ]; then\n"
        . "  RENEW_MONTHS=11\n"
        . "fi\n"
        . "if [ \"$RENEW_MONTHS\" -lt 1 ] || [ \"$RENEW_MONTHS\" -gt 11 ]; then\n"
        . "  RENEW_MONTHS=11\n"
        . "fi\n"
        . "if [ -x /usr/local/sbin/pistar-sslgenerate ]; then\n"
        . "  CERT_FILE=/etc/ssl/certs/pi-star.crt\n"
        . "  if [ ! -f \"$CERT_FILE\" ]; then\n"
        . "    /usr/local/sbin/pistar-sslgenerate force >/dev/null 2>&1 || true\n"
        . "    exit 0\n"
        . "  fi\n"
        . "  NOW=\"$(date +%s)\"\n"
        . "  CERT_AGE=\"$(($(date +%s) - $(stat -c %Y \"$CERT_FILE\" 2>/dev/null)))\"\n"
        . "  if [ \"$CERT_AGE\" -lt \"$((RENEW_MONTHS * 30 * 24 * 60 * 60))\" ]; then\n"
        . "    exit 0\n"
        . "  fi\n"
        . "  /usr/local/sbin/pistar-sslgenerate force >/dev/null 2>&1 || true\n"
        . "fi\n";

    $tmp = tempnam('/tmp', 'pistar-ssl-renew-');
    if ($tmp === false) {
        return;
    }

    file_put_contents($tmp, $scriptBody);
    exec('sudo mount -o remount,rw /');
    exec('sudo install -m 755 -o root -g root ' . escapeshellarg($tmp) . ' ' . escapeshellarg($renewScript));
    exec('sudo mount -o remount,ro /');
    unlink($tmp);
}

function pistar_ssl_remove_renewal_schedule()
{
    exec('sudo rm -f /etc/cron.daily/pistar-ssl-renew > /dev/null 2>&1');
}

function pistar_ssl_reconcile_enabled_state()
{
    $state = pistar_ssl_read_state();
    if (!$state['enabled']) {
        return $state;
    }

    if (!$state['certificate_exists']) {
        pistar_ssl_ensure_certificate();
    }

    if (!$state['renewal_installed']) {
        pistar_ssl_ensure_renewal_schedule();
    }

    return pistar_ssl_read_state();
}

$sslState = pistar_ssl_reconcile_enabled_state();
$saveMsg = '';
$saveErr = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['ssl_apply'])) {
        $enableSsl = (isset($_POST['ssl_enable']) && $_POST['ssl_enable'] === 'ON');
        $renewalMonths = isset($_POST['ssl_renew_months']) ? (int)$_POST['ssl_renew_months'] : 11;

        if ($enableSsl && ($renewalMonths < 1 || $renewalMonths > 11)) {
            $saveErr = 'Auto-renew interval must be between 1 and 11 months when SSL is enabled.';
        } else {
            $errors = pistar_ssl_write_state($enableSsl, $renewalMonths);
            if (!empty($errors)) {
                $saveErr = implode('<br />', $errors);
            } else {
                if ($enableSsl) {
                    pistar_ssl_ensure_certificate();
                    pistar_ssl_ensure_renewal_schedule();
                    $saveMsg = 'SSL enabled. The certificate and auto-renew schedule were installed together so the instance will remain renewal-protected.';
                } else {
                    pistar_ssl_remove_renewal_schedule();
                    $saveMsg = 'SSL disabled. The instance will serve plain HTTP only.';
                }
                $sslState = pistar_ssl_read_state();
            }
        }
    }

    if (isset($_POST['ssl_renew_now'])) {
        pistar_ssl_force_renew();
        $saveMsg = 'Renew now requested. The certificate regeneration has been queued.';
        $sslState = pistar_ssl_read_state();
    }
}

$sslChecked = $sslState['enabled'] ? ' checked="checked"' : '';
$sslStatus = $sslState['enabled'] ? 'Enabled' : 'Disabled';
$renewalMonthsValue = (int)$sslState['renewal_months'];
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD XHTML 1.0 Transitional//EN">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" lang="en">
<head>
<meta name="robots" content="index" />
<meta name="robots" content="follow" />
<meta name="language" content="English" />
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<meta name="Author" content="Andrew Taylor (MW0MWZ)" />
<meta name="Description" content="Pi-Star Expert Editor" />
<meta name="KeyWords" content="Pi-Star" />
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
<meta http-equiv="pragma" content="no-cache" />
<link rel="shortcut icon" href="images/favicon.ico" type="image/x-icon">
<meta http-equiv="Expires" content="0" />
<title>Pi-Star - Digital Voice Dashboard - Expert SSL Manager</title>
<link rel="stylesheet" type="text/css" href="../css/pistar-css.php" />
</head>
<body>
<?php pistar_warnings_render(); ?>
<div class="container">
<?php include './header-menu.inc'; ?>
<div class="contentwide">
  <table width="100%">
    <tr><th>SSL Certificate Manager</th></tr>
    <tr><td align="left">
      <h2 style="margin: 0 0 10px 0;">SSL Certificate Manager</h2>
      <p><strong>SSL status:</strong> <?php echo $sslStatus; ?></p>
      <p><strong>Certificate present:</strong> <?php echo $sslState['certificate_exists'] ? 'Yes' : 'No'; ?></p>
      <p><strong>Auto-renew schedule:</strong> <?php echo $sslState['renewal_installed'] ? 'Installed' : 'Not installed'; ?></p>
      <p>This page manages the instance HTTPS certificate. When SSL is enabled, the certificate is generated and the renewal protection is installed in the same operation so the dashboard cannot be left without a safe renewal path.</p>
      <?php if (!empty($saveMsg)) { echo '<div style="background-color: #c0f0c0; color: #106010; padding: 10px; margin: 0 0 10px 0;">' . htmlspecialchars($saveMsg, ENT_QUOTES, 'UTF-8') . '</div>'; } ?>
      <?php if (!empty($saveErr)) { echo '<div style="background-color: #f8d7da; color: #7f1d1d; padding: 10px; margin: 0 0 10px 0;">' . $saveErr . '</div>'; } ?>
      <form name="sslSettings" method="post" action="" onsubmit="return validateSslForm(this);" style="margin: 12px 0 0 0; padding: 0;">
        <?php csrf_field(); ?>
        <div style="margin-bottom: 12px;">
          <label><input type="checkbox" name="ssl_enable" value="ON"<?php echo $sslChecked; ?> /> Enable SSL</label>
        </div>
        <div style="margin-bottom: 12px;">
          <label for="ssl_renew_months" style="display: inline-block; width: 170px;">Auto-renew interval (1-11 months):</label>
          <input type="number" id="ssl_renew_months" name="ssl_renew_months" min="1" max="11" size="2" maxlength="2" value="<?php echo $renewalMonthsValue; ?>" style="width: 70px; border: 1px solid #888;" />
          <div id="sslRenewError" style="color: #b22222; font-weight: bold; display: none; margin-top: 6px;">Auto-renew interval must be between 1 and 11 months when SSL is enabled.</div>
        </div>
        <div style="margin-top: 8px;">
          <input type="submit" name="ssl_apply" value="Apply" />
          <input type="submit" name="ssl_renew_now" value="Renew Now" />
        </div>
      </form>
      <script type="text/javascript">
        function validateSslForm(form)
        {
            var sslEnabled = form.elements['ssl_enable'] && form.elements['ssl_enable'].checked;
            var renewField = document.getElementById('ssl_renew_months');
            var renewError = document.getElementById('sslRenewError');
            var value = parseInt(renewField.value, 10);

            if (sslEnabled && (isNaN(value) || value < 1 || value > 11)) {
                renewField.style.border = '2px solid #b22222';
                renewField.style.backgroundColor = '#fff4f4';
                renewError.style.display = 'block';
                return false;
            }

            renewField.style.border = '1px solid #888';
            renewField.style.backgroundColor = '#ffffff';
            renewError.style.display = 'none';
            return true;
        }

        function refreshSslRenewValidation()
        {
            var renewField = document.getElementById('ssl_renew_months');
            var renewError = document.getElementById('sslRenewError');
            var value = parseInt(renewField.value, 10);
            var sslEnabled = document.forms['sslSettings'] && document.forms['sslSettings'].elements['ssl_enable'] && document.forms['sslSettings'].elements['ssl_enable'].checked;
            var hasError = sslEnabled && (isNaN(value) || value < 1 || value > 11);

            renewField.style.border = hasError ? '2px solid #b22222' : '1px solid #888';
            renewField.style.backgroundColor = hasError ? '#fff4f4' : '#ffffff';
            renewError.style.display = hasError ? 'block' : 'none';
        }

        (function () {
            var renewField = document.getElementById('ssl_renew_months');
            if (renewField && (!renewField.value || renewField.value === '0')) {
                renewField.value = 11;
            }
            if (renewField) {
                renewField.addEventListener('change', refreshSslRenewValidation);
                renewField.addEventListener('input', refreshSslRenewValidation);
            }
        })();
      </script>
    </td></tr>
  </table>
</div>

<div class="footer">
Pi-Star / Pi-Star Dashboard, &copy; Andy Taylor (MW0MWZ) 2014-<?php echo date("Y"); ?>.<br />
Need help? Click <a style="color: #ffffff;" href="https://www.facebook.com/groups/pistarusergroup/" target="_new">here for the Support Group</a><br />
Get your copy of Pi-Star from <a style="color: #ffffff;" href="http://www.pistar.uk/downloads/" target="_new">here</a>.<br />
</div>

</div>
</body>
</html>
