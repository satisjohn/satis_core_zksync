// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../lib_and_interface/Address.sol";
import "../lib_and_interface/IERC20.sol";
import "../lib_and_interface/SafeERC20.sol";


/**
 * This contract is a simple money pool for deposit.
 * It supports transfer and withdrawal of assets (ETH and ERC20 tokens).
 *
 * This contract uses Openzeppelin's library for ERC20 tokens.
 * When deploying on certain L2s (such as Optimism), it might require slight modifications
 * of the original ERC20 token library, since some ETH functions might not be supported.
 */


contract MoneyPoolRaw {

    using SafeERC20 for IERC20;

    mapping (address => mapping (address => int256)) public clientDepositRecord;
    mapping (address => uint256) public totalLockedAssets;
    mapping (address => mapping (address => uint256)) public instantWithdrawReserve;
    mapping (address => mapping (address => uint256)) public withdrawalQueue;
    mapping (address => uint256) public queueCount;
    mapping (address => uint256) public clientNonce;
    mapping (address => uint256) public satisTokenBalance;
    mapping (address => bool) public workerList;

    address public owner;
    address public proxy;
    address public sigmaProxy;

    event WorkerTakeLockedFund(address workerAddress, address tokenAddress, uint256 takeValue);
    event WorkerDumpBridgedFund(address workerAddress, address[] clientAddressList, address tokenAddress, uint256[] dumpValueList);
    event WorkerDumpInstantWithdrawFund(address workerAddress, address[] _clientAddressList, address _tokenAddress, uint256[] _instantWithdrawValueList);
    event OwnerTakeProfit(address tokenAddress, uint256 takeProfitValue);

    event ChangeOwnership(address newOwner);
    event AddWorkers(address[] addWorkerList);
    event RemoveWorkers(address[] removeWorkerList);
    event ChangeProxy(address newProxy);
    event ChangeSigmaProxy(address newSigmaProxy);

    modifier isOwner() {
        require (msg.sender == owner, "Not an admin");
        _;
    }

    modifier isWorker() {
        require (workerList[msg.sender] == true, "Not a worker");
        _;
    }

    modifier isProxy() {
        require (msg.sender == proxy || msg.sender == sigmaProxy, "Please use proxy contract.");
        _;
    }

    modifier sufficientRebalanceValue(uint256[] memory _queueValueList, uint256 _totalDumpAmount, uint256 _poolAmount) {
        require (_totalDumpAmount > 0 || _queueValueList.length > 0, "Zero dump value and zero queue list length");
        uint256 _queueValue;
        for (uint256 i = 0; i < _queueValueList.length; i++) {
            _queueValue += _queueValueList[i];
        }
        require (_queueValue <= _poolAmount + _totalDumpAmount, "Dump value + pool assets < queue value sum");
        _;
    }

    modifier correctSignatureLength(bytes memory _targetSignature) {
        require (_targetSignature.length == 65, "Incorrect signature length, length must be 65");
        _;
    }

    /**
     * @dev Sets the value for {owner}, owner is also a worker.
     */
    constructor(address _initialProxyAddress, address _initialSigmaProxyAddress) {
        require(_initialProxyAddress != address(0), "Zero address for proxy");
        require(_initialSigmaProxyAddress != address(0), "Zero address for sigma proxy");
        owner = msg.sender;
        workerList[owner] = true;
        proxy = _initialProxyAddress;
        sigmaProxy = _initialSigmaProxyAddress;
    }

    /**
     * @dev Returns client's withdraw nonce.
     */
    function getClientNonce(address _clientAddress) public view returns(uint256) {
        return clientNonce[_clientAddress];
    }

    /**
     * @dev Returns client's net deposit value on this pool (can be negative).
     */
    function getClientDepositRecord(address _clientAddress, address _tokenAddress) public view returns(int256) {
        return clientDepositRecord[_clientAddress][_tokenAddress];
    }

    /**
     * @dev Returns total liquidity available in this pool (excluded client's withdrawal reserves).
     */
    function getLiquidityAmountInPool(address _tokenAddress) public view returns(uint256) {
        return totalLockedAssets[_tokenAddress];
    }

    /**
     * @dev Returns total SATIS token in this pool for Sigma Mining.
     */
    function getSatisTokenAmountInPool(address _tokenAddress) public view returns(uint256) {
        return satisTokenBalance[_tokenAddress];
    }

    /**
     * @dev Returns client's queued value.
     */
    function getClientQueueValue(address[] memory _clientAddressList, address _tokenAddress) public view returns(uint256[] memory) {
        uint256[] memory queueValueList = new uint256[](_clientAddressList.length);
        for (uint i = 0; i < _clientAddressList.length; i++) {
            queueValueList[i] = (withdrawalQueue[_clientAddressList[i]][_tokenAddress]);
        }
        return queueValueList;
    }

    /**
     * @dev Returns client's fast lane value.
     */
    function getClientInstantWithdrawReserve(address[] memory _clientAddressList, address _tokenAddress) public view returns(uint256[] memory) {
        uint256[] memory reserveValueList = new uint256[](_clientAddressList.length);
        for (uint i = 0; i < _clientAddressList.length; i++) {
            reserveValueList[i] = (instantWithdrawReserve[_clientAddressList[i]][_tokenAddress]);
        }
        return reserveValueList;
    }

    /**
     * @dev Returns current queue count of a token.
     */
    function getQueueCount(address _tokenAddress) external view returns(uint256) {
        return queueCount[_tokenAddress];
    }

    /**
     * @dev Transfer the ownership of this contract.
     */
    function transferOwnership(address _newOwner) public isOwner {
        require(_newOwner != address(0), "Zero address for new owner");
        workerList[owner] = false;
        owner = _newOwner;
        workerList[owner] = true;
        emit ChangeOwnership(_newOwner);
    }

    /**
     * @dev Add workers to this contract.
     */
    function addWorkers(address[] memory _addWorkerList) external isOwner {
        for(uint256 i=0; i < _addWorkerList.length; i++) {
            workerList[_addWorkerList[i]] = true;
        }
        emit AddWorkers(_addWorkerList);
    }

    /**
     * @dev Remove workers from this contract.
     */
    function removeWorkers(address[] memory _removeWorkerList) external isOwner {
        for(uint256 i=0; i < _removeWorkerList.length; i++) {
            workerList[_removeWorkerList[i]] = false;
        }
        emit RemoveWorkers(_removeWorkerList);
    }

    /**
     * @dev Update proxy contract address.
     */
    function updateProxyAddress(address _newProxyAddress) public isWorker {
        require(_newProxyAddress != address(0), "Zero address for new proxy");
        proxy = _newProxyAddress;
        emit ChangeProxy(_newProxyAddress);
    }

    /**
     * @dev Update sigma mining proxy contract address.
     */
    function updateSigmaProxyAddress(address _newSigmaProxyAddress) public isWorker {
        require(_newSigmaProxyAddress != address(0), "Zero address for new sigma proxy");
        sigmaProxy = _newSigmaProxyAddress;
        emit ChangeSigmaProxy(_newSigmaProxyAddress);
    }

    /**
     * @dev Show pool owner.
     */
    function getPoolOwner() public view returns(address _admin) {
        _admin = owner;
    }

    /**
     * @dev Check if an address is a worker.
     */
    function verifyWorker(address _workerAddress) public view returns(bool _isWorker) {
        _isWorker = workerList[_workerAddress];
    }

    /**
     * @dev Transfers and lock fund within this contract to support trading positions with optional trading instructions.
     */
    function addFundWithAction(address _clientAddress, address _tokenAddress, uint256 _addValue) external isProxy returns(bool _isDone) {
        IERC20 depositToken = IERC20(_tokenAddress);
        int256 _recordAddValue = int256(_addValue);
        depositToken.safeTransferFrom(_clientAddress, address(this), _addValue);
        clientDepositRecord[_clientAddress][_tokenAddress] += _recordAddValue;
        totalLockedAssets[_tokenAddress] += _addValue;
        _isDone = true;
    }

    /**
     * @dev Internal function, recover signer from signature
     */
    function recoverSignature(bytes32 _targetHash, bytes memory _targetSignature) public pure correctSignatureLength(_targetSignature) returns(address) {
        bytes32 _r;
        bytes32 _s;
        uint8 _v;

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            _r := mload(add(_targetSignature, 32))
            // second 32 bytes
            _s := mload(add(_targetSignature, 64))
            // final byte (first byte of the next 32 bytes)
            _v := and(mload(add(_targetSignature, 65)), 255)
            //_v := byte(0, mload(add(_targetSignature, 96)))
        }

        require (_v == 0 || _v == 1 || _v == 27 || _v == 28, "Recover v value is fundamentally wrong");

        if (_v < 27) {
            _v += 27;
        }

        require (_v == 27 || _v == 28, "Recover v value error: Not 27 or 28");

        return ecrecover(_targetHash, _v, _r, _s);
    }

    /**
     * @dev Hashing message fro ecrevocer function
     */
    function hashingMessage(bytes32 _messageToBeHashed) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32",_messageToBeHashed));
    }


    /**
     * @dev Internal function, convert uint to string
     */
    function uint2str(uint _i) internal pure returns (string memory _uintAsString) {
        if (_i == 0) {
            return "0";
        }
        uint j = _i;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len;
        while (_i != 0) {
            k = k-1;
            uint8 temp = (48 + uint8(_i - _i / 10 * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }

    /**
     * @dev Internal function, convert address to string
     */
    function address2str(address _addr) internal pure returns(string memory) {
        bytes32 value = bytes32(uint256(uint160(_addr)));
        bytes memory alphabet = "0123456789abcdef";

        bytes memory str = new bytes(42);
        str[0] = "0";
        str[1] = "x";
        for (uint i = 0; i < 20; i++) {
            str[2+i*2] = alphabet[uint(uint8(value[i + 12] >> 4))];
            str[3+i*2] = alphabet[uint(uint8(value[i + 12] & 0x0f))];
        }
        return string(str);
    }

    /**
     * @dev Worker unlock fund to instant withdrawal reserve.
     */
    function workerUnlockFund(address[] memory _clientAddressList, address _tokenAddress, uint256[] memory _tokenValueList) public isWorker returns(bool _isDone) {
        for (uint i = 0; i < _clientAddressList.length; i++) {
            instantWithdrawReserve[_clientAddressList[i]][_tokenAddress] += _tokenValueList[i];
            int256 _recordWithdrawValue = int256(_tokenValueList[i]);
            clientDepositRecord[_clientAddressList[i]][_tokenAddress] -= _recordWithdrawValue;
        }
        _isDone = true;
    }

    struct Str {
      string sender;
      string token;
      string withdraw;
      string tier;
      string chainid;
      string pooladdr;
      string nonce;
    }

    /**
     * @dev Verify signature, internal function
     */
    function verifySignature(bytes memory _targetSignature, address _clientAddress, address _tokenAddress, uint256 _withdrawValue, uint256 _tier, uint256 _chainId, address _poolAddress, uint256 _nonce) internal view returns(bool _isDone) {
        require(_chainId == block.chainid, "Incorrect chain ID");
        require(_poolAddress == address(this));
        require(clientNonce[_clientAddress] == _nonce, "Invalid nonce");
        bytes32 _matchHash;
        bytes32 _hashForRecover;
        address _recoveredAddress;
        Str memory str;
        str.sender = address2str(_clientAddress);
        str.token = address2str(_tokenAddress);
        str.withdraw = uint2str(_withdrawValue);
        str.tier = uint2str(_tier);
        str.chainid = uint2str(_chainId);
        str.pooladdr = address2str(_poolAddress);
        str.nonce = uint2str(_nonce);
        _matchHash = keccak256(abi.encode(str.nonce, str.sender, str.token, str.withdraw, str.tier, str.chainid, str.pooladdr));
        _hashForRecover = hashingMessage(_matchHash);
        _recoveredAddress = recoverSignature(_hashForRecover, _targetSignature);
        require (_recoveredAddress == owner, "Incorrect signature");
        _isDone = true;
    }

    /**
     * @dev Tier 1 withdrawal
     */
    function verifyAndWithdrawFund(bytes memory _targetSignature, address _clientAddress, address _tokenAddress, uint256 _withdrawValue, uint256 _tier, uint256 _chainId, address _poolAddress, uint256 _nonce) public isProxy returns(bool _isDone) {
        bool _verification = verifySignature(_targetSignature, _clientAddress, _tokenAddress, _withdrawValue, _tier, _chainId, _poolAddress, _nonce);
        require (_verification, "Signature verification for instant withdrawal fails");
        clientNonce[_clientAddress] = _nonce + 1;

        instantWithdrawReserve[_clientAddress][_tokenAddress] += _withdrawValue;

        int256 _recordWithdrawValue = int256(_withdrawValue);
        clientDepositRecord[_clientAddress][_tokenAddress] -= _recordWithdrawValue;

        _isDone = true;
    }

    /**
     * @dev Tier 2 withdrawal
     */
    function verifyAndQueue(bytes memory _targetSignature, address _clientAddress, address _tokenAddress, uint256 _queueValue, uint256 _tier, uint256 _chainId, address _poolAddress, uint256 _nonce) public isProxy returns(bool _isDone) {
        bool _verification = verifySignature(_targetSignature, _clientAddress, _tokenAddress, _queueValue, _tier, _chainId, _poolAddress, _nonce);
        require (_verification, "Signature verification for queuing fails");
        clientNonce[_clientAddress] = _nonce + 1;
        queueCount[_tokenAddress] += 1;

        withdrawalQueue[_clientAddress][_tokenAddress] += _queueValue;

        int256 _recordQueueValue = int256(_queueValue);
        clientDepositRecord[_clientAddress][_tokenAddress] -= _recordQueueValue;

        _isDone = true;
    }

    /**
     * @dev Verify signature for redeeming SATIS token in Sigma Mining
     */
    function verifyAndRedeemToken(bytes memory _targetSignature, address _clientAddress, address _tokenAddress, uint256 _redeemValue, uint256 _tier, uint256 _chainId, address _poolAddress, uint256 _nonce) external isProxy returns(bool _isDone) {
        bool _verification = verifySignature(_targetSignature, _clientAddress, _tokenAddress, _redeemValue, _tier, _chainId, _poolAddress, _nonce);
        require (_verification == true, "Signature verification fails");
        require (satisTokenBalance[_tokenAddress] >= _redeemValue, "Insifficient SATIS Tokens");
        clientNonce[_clientAddress] = _nonce + 1;

        //Send redeemed token
        IERC20 satisToken = IERC20(_tokenAddress);
        satisToken.safeTransfer(_clientAddress, _redeemValue);
        satisTokenBalance[_tokenAddress] -= _redeemValue;
        _isDone = true;
    }

    /**
     * @dev Fund SATIS token to this contract
     */
    function fundSatisToken(address _tokenAddress, uint256 _fundingValue) external isWorker returns(bool _isDone) {
        IERC20 satisToken = IERC20(_tokenAddress);
        satisToken.safeTransferFrom(msg.sender, address(this), _fundingValue);
        satisTokenBalance[_tokenAddress] += _fundingValue;
        _isDone = true;
    }

    /**
     * @dev Workers take SATIS token from this contract
     */
    function workerTakeSaisToken(address _tokenAddress, uint256 _takingValue) external isWorker returns(bool _isDone) {
        IERC20 satisToken = IERC20(_tokenAddress);
        satisToken.safeTransfer(msg.sender, _takingValue);
        satisTokenBalance[_tokenAddress] -= _takingValue;
        _isDone = true;
    }

    /**
     * @dev Worker taking locked fund for bridging.
     */
    function workerTakeLockedFund(address _tokenAddress, uint256 _takeValue) external isWorker returns(bool _isDone) {
        require(_takeValue <= totalLockedAssets[_tokenAddress], "Taking more than the locked assets in contract");
        IERC20 takeToken = IERC20(_tokenAddress);
        totalLockedAssets[_tokenAddress] -= _takeValue;
        takeToken.safeTransfer(msg.sender, _takeValue);
        emit WorkerTakeLockedFund(msg.sender, _tokenAddress, _takeValue);
        _isDone = true;
    }

    /**
     * @dev Worker dumping crosschain fund from rebalancing.
     */
    function workerDumpRebalancedFund(address[] memory _clientAddressList, address _tokenAddress, uint256[] memory _queueValueList, uint256 _totalDumpAmount) external 
    isWorker sufficientRebalanceValue(_queueValueList, _totalDumpAmount, totalLockedAssets[_tokenAddress]) returns(bool _isDone) {
        require (_clientAddressList.length == _queueValueList.length, "Lists length not match");
        
        // Normal rebalancing
        IERC20 dumpToken = IERC20(_tokenAddress);
        if (_totalDumpAmount > 0) {
            dumpToken.safeTransferFrom(msg.sender, address(this), _totalDumpAmount);
            totalLockedAssets[_tokenAddress] += _totalDumpAmount;
        }

        // Send all fund to queued users
        if (_clientAddressList.length != 0) {
            for (uint256 i=0; i < _clientAddressList.length; i++) {
                dumpToken.safeTransfer(_clientAddressList[i], _queueValueList[i]);
                totalLockedAssets[_tokenAddress] -= _queueValueList[i];
                withdrawalQueue[_clientAddressList[i]][_tokenAddress] -= _queueValueList[i];
            }
            emit WorkerDumpBridgedFund(msg.sender, _clientAddressList, _tokenAddress, _queueValueList);
        }

        // Reset queue count
        if (_clientAddressList.length >= queueCount[_tokenAddress]) {
            queueCount[_tokenAddress] = 0;
        } else {
            queueCount[_tokenAddress] -= _clientAddressList.length;
        }

        _isDone = true;
    }

    /**
     * @dev Worker dumping fund for instant withdrawal.
     */
    function workerDumpInstantWithdrawalFund(address[] memory _clientAddressList, address _tokenAddress, uint256[] memory _instantWithdrawValueList, uint256 _totalDumpAmount) external 
    isWorker sufficientRebalanceValue(_instantWithdrawValueList, _totalDumpAmount, totalLockedAssets[_tokenAddress]) returns(bool _isDone) {
        IERC20 dumpToken = IERC20(_tokenAddress);
        if (_totalDumpAmount > 0) {
            dumpToken.safeTransferFrom(msg.sender, address(this), _totalDumpAmount);
            totalLockedAssets[_tokenAddress] += _totalDumpAmount;
        }
        for (uint256 i=0; i < _clientAddressList.length; i++) {
            dumpToken.safeTransfer(_clientAddressList[i], _instantWithdrawValueList[i]);
            totalLockedAssets[_tokenAddress] -= _instantWithdrawValueList[i];
            instantWithdrawReserve[_clientAddressList[i]][_tokenAddress] -= _instantWithdrawValueList[i];
        }
        emit WorkerDumpInstantWithdrawFund(msg.sender, _clientAddressList, _tokenAddress, _instantWithdrawValueList);
        _isDone = true;
    }

    /**
     * @dev Owner taking profits (charged withdrawal fees).
     */
    function ownerTakeProfit(address _tokenAddress, uint256 _takeProfitValue) external isOwner returns(bool _isDone) {
        require(_takeProfitValue <= totalLockedAssets[_tokenAddress], "Not enough balance to take");
        IERC20 profitToken = IERC20(_tokenAddress);
        profitToken.safeTransfer(msg.sender, _takeProfitValue);
        totalLockedAssets[_tokenAddress] -= _takeProfitValue;
        emit OwnerTakeProfit(_tokenAddress, _takeProfitValue);
        _isDone = true;
    }
}
