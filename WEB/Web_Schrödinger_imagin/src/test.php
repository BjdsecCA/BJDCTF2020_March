<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>Find me in my pass!</title>
	<link href="https://cdn.bootcss.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">

	<style>
		body{
			margin: 0;
			padding: 0;
			background-color: black;
			overflow: hidden;
		}
	</style>
	<script>
		window.onload=function(){
			var drCav = document.getElementById("digitalRain");
			var width = window.innerWidth;
			var height = window.innerHeight;
			drCav.width = width;
			drCav.height = height;
			var fontsize = 7;
			var columns = Math.ceil(width / fontsize);
			var dropLine = [];
			for (var i = 0; i < columns; i++) {
				dropLine[i] = 0;
			}

			if(drCav.getContext){
				var ctx = drCav.getContext("2d");
				timer = setInterval(draw, 50);
			}

			function draw() {
				ctx.fillStyle = "rgba(0, 0, 0, 0.2)";
				ctx.fillRect(0, 0, width, height);

				ctx.fillStyle = "#00FF00";
				ctx.font = fontsize + "px Simsun";
				for (var i = 0; i < columns; i++) {
					var figure = Math.floor(Math.random()*10);

					ctx.fillText(figure, i * fontsize, dropLine[i] * fontsize);
					if (dropLine[i] * fontsize > height || Math.random() > 0.95){
						dropLine[i] = 0;
					}
					dropLine[i]++;
				}
			}
		}
	</script>
</head>
<body>
	<canvas id="digitalRain" style="position:absolute;z-index:-1;border: solid"></canvas>
	<br>
	<div style="text-align: center;margin-top: 500px">
		<form action="" method="post" style="width: 40%;text-align: center;margin-left: 30%;height: 200px">
			<h2><font color="green">I left some good for you in my admin passwd.</h2>
				<h2>So try to get it!
				</font>
			</h2>
			<input style="width:250px;margin-left: 5%;margin-top: 30px" class="form-control" type="text" name="id" required>
			<input style="width:250px;margin-left: 47%;margin-top: -34px" class="form-control" type="password" name="pw" required>
			<button style="margin-top:-57px;margin-left: 85%" type="submit" class="btn btn-primary">Login</button>
		</form>
	</div>
</body>

<?php
if(isset($_POST['id']) and isset($_POST['pw'])){
	if($_POST['id'] != "admin"){
		echo "<script>alert('wrong user!')</script>";
	}
	else if($_POST['pw'] != "av32011091"){
		echo "<script>alert('wrong pass!')</script>";
	}
	else{
		echo "<script>alert('Congratuations! Let's listen Rebecca together!')</script>";
	}
}
