<?php
session_start();
error_reporting(0);
if(isset($_POST['url'])){
	setcookie("dXNlcg", base64_encode(time()), time() + 360000);
	$_SESSION['url'] = $_POST['url'];
	echo "<script>alert('URL Confirmed.')</script>";
	echo "<script>location.replace(location.href);</script>";
}	



if(isset($_GET['check'])){
	if(isset($_COOKIE['dXNlcg'])){
		$time = base64_decode($_COOKIE['dXNlcg']);
		$url = $_SESSION['url'];
		$sub = time() - $time;
		$rate = log($sub) * 4.7;
		if(preg_match("/test\.php/", $url)){
			if($rate > 99){
				$s = "Burst successed! The passwd is av11664517@1583985203.";
			}
			else{
				$s = "Burst failed, maybe you should try longer.";
			}
		}
		else{
			$s = "Burst failed, maybe you should try longer.";
		}
		setcookie("dXNlcg", "", time() - 1);
		unset($_SESSION['url']);
		echo "<script>if(confirm(\"$s\")){ location.href=\"index.php\"; }</script>";
	}
	else{
		echo "<script>if(confirm('You have no target!')){ location.href='index.php'; }</script>";
	}
}
?>
<title>imagin's Schrödinger Login Fucker</title>
<link href="https://cdn.bootcss.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">
<script type="text/javascript" src="jQuery.js"></script>
<div style="margin-top: 5%;margin-left: 20%;width: 60%">
	<h1>Welcome to imagin's Schrödinger Login Fucker!</h1>
	<h3>
		<br>
		<p style="margin-left: 20px">It's the most beautiful interface I can write（'▿'）</p>
		<br>
		<p>Intro:</p>
		<p style="margin-left: 20px">You can give a wibsite to this page and this page will automatically identify various parameters of the target and try to burst the password.</p>
		<p style="margin-left: 20px">The longer the compute time is, the higher the success rate of the burst is.</p>
		<p style="margin-left: 20px">But before the final result is checked, no one knows whether to burst out the password. We call it the superposition state of burst and unburst</p>
		<p style="margin-left: 20px">You can check the progress at any time, but once you check the progress, this website will stop bursting and delete the relevant progress, which we call the collapse of the superposition state.</p>
		<p style="margin-left: 20px">If the CPU of the server is idle, it must be able to burst out the password you want very soon :)</p>
		<p style="margin-left: 20px">Enjoy it!</p>
		<p style="margin-right: 10%;float:right;">imagin@1580308166</p>
	</h3>
	<h3><font color="white">Note : Remenmber to remove test.php!</font></h3>
</div>


<div>
	<form style="margin-top: 100px;margin-left: 20%;width: 60%" method="POST" action="">
		<input style="width:350px;margin-left: 20%;margin-top: 15px" class="form-control" type="text" name="url" placeholder="input a victim" required>
		<button style="margin-top:-35px;margin-left: 56%" type="submit" class="btn btn-primary">Input</button>
	</form>
	<form action="" method="GET">
	<button style="margin-top:-49px;margin-left: 60%" type="submit" class="btn btn-danger" name="check">Check</button></form>	
</div>

<?php


if(isset($_COOKIE['dXNlcg'])){
	$time = base64_decode($_COOKIE['dXNlcg']);
	$url = $_SESSION['url'];
	$sub = time() - $time;
	echo "
	<div style = 'margin-left:20%'>
	<h3>Load of Server CPU<span id='span1' style = 'margin-left:2%'></span></h3>
	<h3>Already burst <span id='span2'></span> sec, <span id='span3'></span> p/s</h3>
	<h3>Forecast success rate <span id='span4'></span>%</h3>
	<script>_();__($sub);___();script($sub);</script>
	</div>";

}

else{
	if(isset($_GET['check'])){
		echo "<script language=JavaScript> location.href = 'index.php';</script>";
	}
	echo "
	<div style = 'margin-left:20%'>
	<h3>Load of Server CPU<span id='span1' style = 'margin-left:2%'></span></h3>
	<script>_A();</script>
	</div>";
}
?>


