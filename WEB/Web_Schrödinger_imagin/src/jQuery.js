function _A(){
	var num = 13;
	var rate = 0.5;
	var c = 1;
	var t = setInterval(function(){
		var symbol = Math.random() > rate ? 1 : -1;
		var add_number = Math.random() * symbol * c;
		if(num + add_number > 100 || num + add_number < 10){
		}
		else{
			num += add_number;
			var span1 = document.getElementById('span1');
			span1.innerText = num + '%';
		}
	}, 100);
}

function _(){
	var num = 13;
	var rate = 0.2;
	var c = 10;
	var t = setInterval(function(){
		var symbol = Math.random() > rate ? 1 : -1;
		var add_number = Math.random() * symbol * c;
		if(num + add_number > 100 || num + add_number < 10){

		}
		else{
			num += add_number;
			var span1 = document.getElementById('span1');
			span1.innerText = num + '%';
		}
	}, 100);
}

function __(sub){
	var s = sub;
	var t = setInterval(function(){
		s += 1;
		var span2 = document.getElementById('span2');
		span2.innerText = s;
	}, 1000);
}

function ___(){
	var t = setInterval(function(){
		var pwd = Math.floor(Math.random()* (150000 - 120000) + 120000);
		span3.innerText = pwd;
	}, 1000);
}

function script(sub){
	var rate = sub;
	var t = setInterval(function(){
		rate += 1;
		span4.innerText = Math.log(rate) * 4.7;
	}, 1000);
}
