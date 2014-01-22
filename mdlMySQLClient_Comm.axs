MODULE_NAME='mdlMySQLClient_Comm'(DEV vdvVirtual, DEV dvDevice)
(***********************************************************)
(***********************************************************)
(*  FILE_LAST_MODIFIED_ON: 04/04/2006  AT: 11:33:16        *)
(***********************************************************)
(* System Type : NetLinx                                   *)
(***********************************************************)
(* REV HISTORY:                                            *)
(***********************************************************)
(*
    $History: $
    Remember that mysql.user.Password stores SHA1(SHA1(password))
	The server sends a random string (scramble) to the client
	the client calculates:
	    stage1_hash = SHA1(password), using the password that the user has entered.
	    token = SHA1(scramble + SHA1(stage1_hash)) XOR stage1_hash
	the client sends the token to the server
	the server calculates
	    stage1_hash' = token XOR SHA1(scramble + mysql.user.Password)
	the server compares SHA1(stage1_hash') and mysql.user.Password
	If they are the same, the password is okay.
	
    (Note SHA1(A+B) is the SHA1 of the concatenation of A with B.)
    SHA-1 is a cryptographic hash function designed by the United States National Security Agency
    SHA-1 produces a 160-bit message digest
    
    string:		SHA1:
    'password'		5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
    'secret'		e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4
    'root'		dc76e9f0c0006e8f919e0c515c66dbba3982f785
    'admin'		d033e22ae348aeb5660fc2140aec35850c4da997
    ''			da39a3ee5e6b4b0d3255bfef95601890afd80709
*)    
(***********************************************************)
(*          DEVICE NUMBER DEFINITIONS GO BELOW             *)
(***********************************************************)
DEFINE_DEVICE

(***********************************************************)
(*               CONSTANT DEFINITIONS GO BELOW             *)
(***********************************************************)
DEFINE_CONSTANT
TIMELINE_ID_1				=	    1
MAX_BUFFER_LENGTH			=	 3000

/*	COMMAND CONSTANTS	*/
COMMAND_INTERVAL			=	 1000
MAX_BUFFER_COMMANDS			=	  300
MAX_COMMAND_LENGTH			=	  300
CMD_SET_PROPERTY			=	    1
CMD_GET_PROPERTY			=	    2
CMD_SET_LOG				=	    3
CMD_GET_LOG				=	    4
CMD_SQL_USE				=	    5	// for selecting a specific database
CMD_SQL_COMMIT				=	    6	// for committing changes to a specific database
CMD_SQL_ROLLBACK			=	    7	// for rolling back changes to a specific database
CMD_SQL_CREATE				=	    8	// Creates a new table, a view of a table, or other object in database
CMD_SQL_ALTER				=	    9	// Modifies an existing database object, such as a table.
CMD_SQL_DROP				=	   10	// Deletes an entire table, a view of a table or other object in the database
CMD_SQL_INSERT				=	   11	// Creates a record
CMD_SQL_UPDATE				=	   12	// Modifies records
CMD_SQL_DELETE				=	   13	// Deletes records
CMD_SQL_GRANT				=	   14	// Gives a privilege to user
CMD_SQL_REVOKE				=	   15	// Takes back privileges granted from user
CMD_SQL_SELECT				=	   16	// Retrieves certain records from one or more tables
CMD_HASH_TEST				=	   17	// Should be a secret command to test SHA1HMAC hashing
CMD_PASSTHRU				=	   18
CHAR acCommands[][MAX_COMMAND_LENGTH]	= { 'PROPERTY', '?PROPERTY', 'LOG', '?LOG', 'USE', 'COMMIT', 'ROLLBACK', 'CREATE', 'ALTER', 'DROP', 'INSERT', 'UPDATE', 'DELETE', 'GRANT', 'REVOKE', 'SELECT', 'HASH', 'PASSTHRU' }

// MODULE PROPERTIES
MAX_PROPNAME_LENGTH			=	   30
MAX_PROPVAL_LENGTH			=	   30
PROPERTY_HOSTNAME			=	    1
PROPERTY_IPADDRESS			=	    2
PROPERTY_IPPORT				=	    3
PROPERTY_USERNAME			=	    4
PROPERTY_PASSWORD			=	    5
PROPERTY_POLLINTERVAL			=	    6
CHAR acProperties[][MAX_PROPNAME_LENGTH]= { 'hostname', 'ipaddress', 'ipport', 'username', 'password', 'pollinterval'}

// IP PROPERTIES
MAX_IPADDRESS_LENGTH			=	   15
MAX_USERNAME_LENGTH			=	   63
MAX_PASSWORD_LENGTH			=	   63
MAX_HOSTNAME_LENGTH 			=	   63 	// what is the maximum length of a hostname ???

// INITIAL IP CONNECTION STATUS
SLONG IP_STATUS_UNKNOWN			=          -1

MIN_POLL_TIME				=	 1000
MAX_POLL_TIME				=	10000

// LOG LEVELS
CHAR acLogLevels[][8] = {'error', 'warning', 'info', 'debug'}


MAX_COLUMNNAME_LENGTH = 12

CONSTANT COM_SLEEP			=	$00;	//   COM_SLEEP           	(none, this is an internal thread state)
CONSTANT COM_QUIT			=	$01;	//   COM_QUIT            	mysql_close
CONSTANT COM_INIT_DB			=	$02;	//   COM_INIT_DB         	mysql_select_db 
CONSTANT COM_QUERY			=       $03;	//   COM_QUERY           	mysql_real_query
CONSTANT COM_FIELD_LIST			=       $04;	//   COM_FIELD_LIST      	mysql_list_fields
CONSTANT COM_CREATE_DB			=       $05;	//   COM_CREATE_DB       	mysql_create_db (deprecated)
CONSTANT COM_DROP_DB			=       $06;	//   COM_DROP_DB         	mysql_drop_db (deprecated)
CONSTANT COM_REFRESH			=       $07;	//   COM_REFRESH         	mysql_refresh
CONSTANT COM_SHUTDOWN			=       $08;	//   COM_SHUTDOWN        	mysql_shutdown
CONSTANT COM_STATISTICS			=       $09;	//   COM_STATISTICS      	mysql_stat
CONSTANT COM_PROCESS_INFO		=       $0A;	//   COM_PROCESS_INFO    	mysql_list_processes
CONSTANT COM_CONNECT			=       $0B;	//   COM_CONNECT         	(none, this is an internal thread state)
CONSTANT COM_PROCESS_KILL		=       $0C;	//   COM_PROCESS_KILL    	mysql_kill
CONSTANT COM_DEBUG			=       $0D;	//   COM_DEBUG           	mysql_dump_debug_info
CONSTANT COM_PING			=       $0E;	//   COM_PING            	mysql_ping
CONSTANT COM_TIME			=       $0F;	//   COM_TIME            	(none, this is an internal thread state)
CONSTANT COM_DELAYED_INSERT		=	$10;	//   COM_DELAYED_INSERT  	(none, this is an internal thread state)
CONSTANT COM_CHANGE_USER		=	$11;	//   COM_CHANGE_USER     	mysql_change_user
CONSTANT COM_BINLOG_DUM			=	$12;	//   COM_BINLOG_DUMP     	sent by the slave IO thread to request a binlog
CONSTANT COM_TABLE_DUMP			=	$13;	//   COM_TABLE_DUMP      	LOAD TABLE ... FROM MASTER (deprecated)
CONSTANT COM_CONNECT_OUT		=	$14;	//   COM_CONNECT_OUT     	(none, this is an internal thread state)
CONSTANT COM_REGISTER_SLAVE		=	$15;	//   COM_REGISTER_SLAVE  	sent by the slave to register with the master (optional)
CONSTANT COM_STMT_PREPARE		=	$16;	//   COM_STMT_PREPARE    	mysql_stmt_prepare
CONSTANT COM_STMT_EXECUTE		=	$17;	//   COM_STMT_EXECUTE    	mysql_stmt_execute
CONSTANT COM_STMT_SEND_LONG_DATA	=	$18;	//   COM_STMT_SEND_LONG_DATA 	mysql_stmt_send_long_data
CONSTANT COM_STMT_CLOSE			=	$19;	//   COM_STMT_CLOSE      	mysql_stmt_close
CONSTANT COM_STMT_RESET			=	$1A;	//   COM_STMT_RESET      	mysql_stmt_reset
CONSTANT COM_SET_OPTION			=	$1B;	//   COM_SET_OPTION      	mysql_set_server_option
CONSTANT COM_STMT_FETCH			=	$1C;	//   COM_STMT_FETCH      	mysql_stmt_fetch

MAX_CHARS		=	256
MAX_SHA1HASH_LENGTH	=	 20

#INCLUDE 'SNAPI.axi'
(***********************************************************)
(*              DATA TYPE DEFINITIONS GO BELOW             *)
(***********************************************************)
DEFINE_TYPE
STRUCTURE _uIpDevice
{
    CHAR acHostname[MAX_HOSTNAME_LENGTH]	// what is the maximum length of a hostname ???
    CHAR acIpAddress[MAX_IPADDRESS_LENGTH]
    INTEGER nIpPort
}
STRUCTURE _uUser
{
    CHAR acUsername[MAX_USERNAME_LENGTH]
    CHAR acPassword[MAX_PASSWORD_LENGTH]
}

STRUCTURE _uServerGreeting
{
    CHAR acServerVersion[32]
    INTEGER nThreadID
    CHAR acSalt[8]
    LONG lServerCapabilities1
    INTEGER nCharset
    LONG lServerStatus
    LONG lServerCapabilities2
    // length of auth_plugin_data , else [00]
    CHAR acReserved[10]
    CHAR acSubSalt[12]
    CHAR acAuthPluginName[32]
}
STRUCTURE _uSHA1HMAC
{
    CHAR acSalt[MAX_SHA1HASH_LENGTH]
    CHAR acPassword[MAX_PASSWORD_LENGTH]
    CHAR acHash[MAX_SHA1HASH_LENGTH]
}

(***********************************************************)
(*               VARIABLE DEFINITIONS GO BELOW             *)
(***********************************************************)
DEFINE_VARIABLE
VOLATILE _uIpDevice uIpDevice
VOLATILE _uUser uUser
VOLATILE CHAR acBuffer[MAX_BUFFER_LENGTH]
VOLATILE LONG lTimeArray[] 		= 	  {0,COMMAND_INTERVAL}
VOLATILE INTEGER nTxWrite, nTxRead
VOLATILE CHAR acCommandBuffer[MAX_BUFFER_COMMANDS][MAX_COMMAND_LENGTH]
VOLATILE SLONG slIpConnection
VOLATILE CHAR acServerAddress[MAX_HOSTNAME_LENGTH]
VOLATILE INTEGER nTimeLineRepetition

CONSTANT INTEGER eSTATE_INACTIVE	=	   0
CONSTANT INTEGER eSTATE_START		=	   1
CONSTANT INTEGER eSTATE_IDLE		=	   2
VOLATILE INTEGER eCommState		= eSTATE_INACTIVE
VOLATILE INTEGER nAwaitResponse

// MYSQL related
_uServerGreeting uServerGreeting
_uSHA1HMAC uSHA1HMAC
CHAR acPacketLength[3]
INTEGER nPacketNumber
INTEGER nPacketLength
INTEGER nNumberOfFields
CHAR cStatus
CHAR acColumns[12][MAX_COLUMNNAME_LENGTH]
CHAR acRows[24][100]
CHAR acItems[12][MAX_COLUMNNAME_LENGTH]
VOLATILE CHAR acLoginState[32]
CHAR acClientCapabilities[] = { $85, $A6}
CHAR acExtClientCapabilities[] = { $7F, $00}
CHAR acMaxPacketBytes[] = {$00,$00,$00,$40}
CHAR cCharSet = $21
CHAR acNullFiller[] = {$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00}

CHAR acTestPwd[] = 'brianh'
INTEGER nAttempt
(***********************************************************)
(*               LATCHING DEFINITIONS GO BELOW             *)
(***********************************************************)
DEFINE_LATCHING

(***********************************************************)
(*       MUTUALLY EXCLUSIVE DEFINITIONS GO BELOW           *)
(***********************************************************)
DEFINE_MUTUALLY_EXCLUSIVE

(***********************************************************)
(*        SUBROUTINE/FUNCTION DEFINITIONS GO BELOW         *)
(***********************************************************)
(* EXAMPLE: DEFINE_FUNCTION <RETURN_TYPE> <NAME> (<PARAMETERS>) *)
(* EXAMPLE: DEFINE_CALL '<NAME>' (<PARAMETERS>) *)
DEFINE_FUNCTION LONG LROTATE_LEFT(LONG lVar, INTEGER nSteps)
{
    LONG lResult
    INTEGER nIdx
    
    lResult = lVar
    FOR(nIdx = 1; nIdx <= nSteps; nIdx++) {
	IF(lResult BAND $80000000 ) {
	    // cary over...
	    lResult = lResult << 1
	    lResult = lResult + 1
	}
	ELSE {
	    lResult = lResult << 1
	}
    }
    
    RETURN lResult
}
DEFINE_FUNCTION CHAR[20] SHA1(CHAR acData[])
{
    STACK_VAR LONG lWords[80]
    STACK_VAR INTEGER nMessageBitLength
    STACK_VAR INTEGER nMessageLength
    STACK_VAR INTEGER nChunks
    STACK_VAR INTEGER nArray[MAX_CHARS/2]

    STACK_VAR LONG h0
    STACK_VAR LONG h1
    STACK_VAR LONG h2
    STACK_VAR LONG h3
    STACK_VAR LONG h4

    STACK_VAR SINTEGER snResult
    STACK_VAR INTEGER nIdx
    STACK_VAR INTEGER nCharIdx
    STACK_VAR INTEGER nWordIdx
    STACK_VAR INTEGER nChunkIdx
    STACK_VAR LONG VarA
    STACK_VAR LONG VarB
    STACK_VAR LONG VarC
    STACK_VAR LONG VarD
    STACK_VAR LONG VarE
    STACK_VAR LONG VarF
    STACK_VAR LONG VarK
    STACK_VAR LONG lVarTemp
    
    STACK_VAR CHAR SHA1Hash[20]
    
    // Step 0: Initialize some variables
    h0 = $67452301
    h1 = $EFCDAB89
    h2 = $98BADCFE
    h3 = $10325476
    h4 = $C3D2E1F0

    // clear array before use
    FOR(nIdx = 1;nIdx <= 128; nIdx++) {
	nArray[nIdx] = 0
    }

    // Step 4: Convert numbers into binary
    nMessageLength = LENGTH_STRING(acData)
    nMessageBitLength = nMessageLength*8
    FOR(nCharIdx = 1;nCharIdx <= nMessageLength; nCharIdx++) {
	IF((acData[nCharIdx] >= 0) && (acData[nCharIdx] <= 255)) {
	    // optimize memory usage by adding 2 chars into 1 int
	    nArray[((nCharIdx-1)/2)+1] = nArray[((nCharIdx-1)/2)+1] + (acData[nCharIdx] * POWER_VALUE(256,nCharIdx%2))
	}
	ELSE {
	    snResult = -1
	    AMX_LOG(AMX_ERROR,"'invalid character found [',ITOA(nCharIdx),']',ITOA(acData[nCharIdx]),'  ... unable to proceed SHA1'")
	    BREAK;
	}
    }
    
    // if all chars are valid, continue
    IF(!snResult) {
	
	//Step 5: Add '1' to the end
	nArray[((nCharIdx-1)/2)+1] = nArray[((nCharIdx-1)/2)+1] + $80 * POWER_VALUE(256,nCharIdx%2)
	
	//Step 6: Append '0's' to the end
	    //add zeros to the end until the length of the message is congruent to 448 mod 512
	
	//Step 6.1: Append original message length
//	nArray[((((nIdx-1)/64)+1)*32) - 1]	= nMessageBitLength BAND $FF00	// MSB
	nArray[(((nCharIdx+7)/64)+1)*32]		= nMessageBitLength
	    // 448 bits -> 56 bytes (idx <= 56)  512 bits -> 64 bits
	nChunks = ((nCharIdx+7)/64)+1
	
	FOR(nChunkIdx = 1; nChunkIdx <= nChunks; nChunkIdx++) {
	    // clear previous extended words
	    FOR(nWordIdx = 1; nWordIdx <= 80; nWordIdx++) {
		lWords[nWordIdx] = 0
	    }
	    // set new 16 word chunck
	    FOR(nWordIdx = 1; nWordIdx <= 16; nWordIdx++) {
		nIdx = ((nWordIdx*2) + (nChunkIdx - 1)*32)
		lWords[nWordIdx] = nArray[nIdx-1]*65536 + nArray[nIdx]
	    }
	    
	    //Step 9: 'Extend' into 80 words
	    FOR(nWordIdx = 17; nWordIdx <= 80; nWordIdx++) {
		lWords[nWordIdx] = (((lWords[nWordIdx-3] BXOR lWords[nWordIdx-8]) BXOR lWords[nWordIdx-14]) BXOR lWords[nWordIdx-16])
		//Step 9.2: Left rotate
		lWords[nWordIdx] = LROTATE_LEFT(lWords[nWordIdx], 1)
	    }
	    
	    //Step 10: Initialize some variables
	    VarA = h0
	    VarB = h1
	    VarC = h2
	    VarD = h3
	    VarE = h4
	    
	    //Step 11: The main loop
	    FOR(nWordIdx = 1; nWordIdx <= 80; nWordIdx++) {
		//Step 11.1: Four choices
		SELECT {
		    ACTIVE(nWordIdx <= 20): {
			// function 1
			VarF = (VarB BAND VarC) BOR (~VarB BAND VarD)
			Vark = $5A827999
		    }		
		    ACTIVE(nWordIdx > 20 && nWordIdx <= 40): {
			// function 2
			VarF = ((VarB BXOR VarC) BXOR VarD)
			Vark = $6ED9EBA1
		    }		
		    ACTIVE(nWordIdx > 40 && nWordIdx <= 60): {
			// function 3
			VarF = (VarB BAND VarC) BOR (VarB BAND VarD) BOR (VarC BAND VarD)
			Vark = $8F1BBCDC
		    }		
		    ACTIVE(nWordIdx > 60 && nWordIdx <= 80): {
			// function 4
			VarF = ((VarB BXOR VarC) BXOR VarD)
			Vark = $CA62C1D6
		    }
		}
		
		//Step 11.2: Put them together
		lVarTemp = LROTATE_LEFT(VarA, 5) + VarF + VarE + VarK + lWords[nWordIdx]
		VarE = VarD
		VarD = VarC
		VarC = LROTATE_LEFT(VarB , 30)
		VarB = VarA
		VarA = lVarTemp
	    }
	    
	    //Step 12: The end
	    h0 = h0 + VarA
	    h1 = h1 + VarB
	    h2 = h2 + VarC
	    h3 = h3 + VarD
	    h4 = h4 + VarE
	}
    }
    
    SHA1Hash[1]  = TYPE_CAST(h0 / 16777216)
    SHA1Hash[2]  = TYPE_CAST(h0 / 65536)
    SHA1Hash[3]  = TYPE_CAST(h0 / 256)
    SHA1Hash[4]  = TYPE_CAST(h0 % 256)
    
    SHA1Hash[5]  = TYPE_CAST(h1 / 16777216)
    SHA1Hash[6]  = TYPE_CAST(h1 / 65536)
    SHA1Hash[7]  = TYPE_CAST(h1 / 256)
    SHA1Hash[8]  = TYPE_CAST(h1 % 256)
    
    SHA1Hash[9]  = TYPE_CAST(h2 / 16777216)
    SHA1Hash[10] = TYPE_CAST(h2 / 65536)
    SHA1Hash[11] = TYPE_CAST(h2 / 256)
    SHA1Hash[12] = TYPE_CAST(h2 % 256)
    
    SHA1Hash[13] = TYPE_CAST(h3 / 16777216)
    SHA1Hash[14] = TYPE_CAST(h3 / 65536)
    SHA1Hash[15] = TYPE_CAST(h3 / 256)
    SHA1Hash[16] = TYPE_CAST(h3 % 256)
    
    SHA1Hash[17] = TYPE_CAST(h4 / 16777216)
    SHA1Hash[18] = TYPE_CAST(h4 / 65536)
    SHA1Hash[19] = TYPE_CAST(h4 / 256)
    SHA1Hash[20] = TYPE_CAST(h4 % 256)
    
    SET_LENGTH_STRING(SHA1Hash, 20)
    RETURN SHA1Hash
}
DEFINE_FUNCTION CHAR[40] fnEncryptSHA1WithMySQLSalt(CHAR acData[], CHAR acSalt[])
{
    INTEGER nIdx
    CHAR acStage1_hash[20]
    CHAR acStage2_hash[20]
    CHAR acStage3_hash[40]
    CHAR acStage4_hash[20]
    CHAR acToken[20]
    
    CHAR acMySqlHashedPassword[20]

    acStage1_hash = SHA1(acData)
    acStage2_hash = SHA1(acStage1_hash)
    acStage3_hash = "acSalt,acStage2_hash"
    acStage4_hash = SHA1("acStage3_hash")
    FOR(nIdx = 1; nIdx <= MAX_SHA1HASH_LENGTH; nIdx++) {
	acToken[nIdx] = (acStage4_hash[nIdx] BXOR acStage1_hash[nIdx])
    }
    SET_LENGTH_STRING(acToken, 20)
    
    RETURN acToken
}
DEFINE_FUNCTION CHAR[100] GET_IP_ERROR (LONG lIpError)
{
    SWITCH (lIpError) {
	CASE 0:
	  RETURN "";
	CASE 2:
	  RETURN "'IP ERROR (',ITOA(lIpError),'): General Failure (IP_CLIENT_OPEN/IP_SERVER_OPEN)'";
	CASE 4:
	  RETURN "'IP ERROR (',ITOA(lIpError),'): unknown host or DNS error (IP_CLIENT_OPEN)'";
	CASE 6:
	  RETURN "'IP ERROR (',ITOA(lIpError),'): connection refused (IP_CLIENT_OPEN)'";
	CASE 7:
	  RETURN "'IP ERROR (',ITOA(lIpError),'): connection timed out (IP_CLIENT_OPEN)'";
	CASE 8:
	  RETURN "'IP ERROR (',ITOA(lIpError),'): unknown connection error (IP_CLIENT_OPEN)'";
	CASE 14:
	  RETURN "'IP ERROR (',ITOA(lIpError),'): local port already used (IP_CLIENT_OPEN/IP_SERVER_OPEN)'";
	CASE 16:
	  RETURN "'IP ERROR (',ITOA(lIpError),'): too many open sockets (IP_CLIENT_OPEN/IP_SERVER_OPEN)'";
	CASE 10:
	  RETURN "'IP ERROR (',ITOA(lIpError),'): Binding error (IP_SERVER_OPEN)'";
	CASE 11:
	  RETURN "'IP ERROR (',ITOA(lIpError),'): Listening error (IP_SERVER_OPEN)'";
	CASE 15:
	  RETURN "'IP ERROR (',ITOA(lIpError),'): UDP socket already listening (IP_SERVER_OPEN)'";
	CASE 9:
	  RETURN "'IP ERROR (',ITOA(lIpError),'): Already closed (IP_CLIENT_CLOSE/IP_SERVER_CLOSE)'";
	CASE 17:
	  RETURN "'IP ERROR (',ITOA(lIpError),'): Local port not open, can not send string (IP_CLIENT_OPEN)'";	
	DEFAULT:
	  RETURN "'IP ERROR (',ITOA(lIpError),'): Unknown'";
    }
}

DEFINE_FUNCTION fnAddTxBuffer(CHAR acData[])
{
    IF(((nTxWrite % MAX_BUFFER_COMMANDS) + 1) ==  nTxRead) {
	// this will overwrite data!!!
	AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': this will overwrite data!!! Please increase send speed to real device'")
	AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': or increase buffer size MAX_COMMANDS'")
    }
    ELSE {
	IF(LENGTH_STRING(acData) > MAX_COMMAND_LENGTH) {
	    AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': this command length(',ITOA(LENGTH_STRING(acData)),') doesnt fit!!! Please increase buffer entry length'")
	}
	ELSE {
	    acCommandBuffer[nTxWrite] = "acData"
	    nTxWrite = (nTxWrite % MAX_BUFFER_COMMANDS) + 1
	}
    }
}

DEFINE_FUNCTION fnParseCommand(INTEGER nCmdIdx, CHAR acValue[]) {
    SWITCH(nCmdIdx) {
	CASE CMD_SET_PROPERTY:
	    fnParseSetProperty(acValue)
	    BREAK;
	CASE CMD_GET_PROPERTY:
	    fnParseGetProperty(acValue)
	    BREAK;
	CASE CMD_SET_LOG:
	    fnParseSetLogLevel(acValue)
	    BREAK;
	CASE CMD_GET_LOG:
	    fnParseGetLogLevel()
	    BREAK;
	CASE CMD_SQL_USE:
	    fnParseSqlQueryUse(acValue)
	    BREAK;
	CASE CMD_SQL_COMMIT:
	    fnParseSqlQueryUse(acValue)
	    BREAK;
	CASE CMD_SQL_ROLLBACK:
	    fnParseSqlQueryUse(acValue)
	    BREAK;	
	CASE CMD_SQL_CREATE:
	    fnParseSqlQueryCreate(acValue)
	    BREAK;
	CASE CMD_SQL_ALTER:
	    fnParseSqlQueryAlter(acValue)
	    BREAK;
	CASE CMD_SQL_DROP:
	    fnParseSqlQueryDrop(acValue)
	    BREAK;
	CASE CMD_SQL_INSERT:
	    fnParseSqlQueryInsert(acValue)
	    BREAK;
	CASE CMD_SQL_UPDATE:
	    fnParseSqlQueryUpdate(acValue)
	    BREAK;
	CASE CMD_SQL_DELETE:
	    fnParseSqlQueryDelete(acValue)
	    BREAK;
	CASE CMD_SQL_GRANT:
	    fnParseSqlQueryGrant(acValue)
	    BREAK;
	CASE CMD_SQL_REVOKE:
	    fnParseSqlQueryRevoke(acValue)
	    BREAK;
	    BREAK;
	CASE CMD_SQL_SELECT:
	    fnParseSqlQuerySelect(acValue)
	    BREAK;
	CASE CMD_PASSTHRU:
	    fnAddTxBuffer(acValue)
	    BREAK;
	CASE CMD_HASH_TEST:
	    SEND_STRING vdvVirtual,"fnEncryptSHA1WithMySQLSalt(acTestPwd, acValue)"
	    BREAK;
	DEFAULT:
	    AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnParseCommand(',ITOA(nCmdIdx),') unhandled'")
	    BREAK;
    }
}

    DEFINE_FUNCTION fnParseSetProperty(CHAR acPropertyString[])
{
    CHAR acPropertyName[MAX_PROPNAME_LENGTH]
    CHAR acPropertyValue[MAX_PROPVAL_LENGTH]
    INTEGER nIdx
    
    acPropertyName = REMOVE_STRING(acPropertyString,':', 1)
    SET_LENGTH_STRING(acPropertyName, LENGTH_STRING(acPropertyName)-1)
    acPropertyName = LOWER_STRING(acPropertyName)
    acPropertyValue = acPropertyString
    
    FOR(nIdx = 1; nIdx <= LENGTH_ARRAY(acProperties); nIdx++) {
	IF(acProperties[nIdx] == acPropertyName) {
	    BREAK;
	}
    }
    
    SWITCH(nIdx) {
	CASE PROPERTY_HOSTNAME:
	    IF(fnSetPropertyHostname(acPropertyValue)) {
		SEND_STRING vdvVirtual,"'invalid hostname'"
	    }
	    BREAK;
	CASE PROPERTY_IPADDRESS:
	    IF(fnSetPropertyIpAddress(acPropertyValue)) {
		SEND_STRING vdvVirtual,"'invalid ip address'"
	    }
	    BREAK;
	CASE PROPERTY_IPPORT:
	    IF(fnSetPropertyIpPort(acPropertyValue)) {
		SEND_STRING vdvVirtual,"'invalid ip port'"
	    }
	    BREAK;
	CASE PROPERTY_USERNAME:
	    IF(fnSetPropertyUsername(acPropertyValue)) {
		SEND_STRING vdvVirtual,"'invalid username'"
	    }
	    BREAK;
	CASE PROPERTY_PASSWORD:
	    IF(fnSetPropertyPassword(acPropertyValue)) {
		SEND_STRING vdvVirtual,"'invalid password'"
	    }
	    BREAK;
	CASE PROPERTY_POLLINTERVAL:
	    IF(fnSetPropertyPollInterval(acPropertyValue)) {
		SEND_STRING vdvVirtual,"'invalid poll interval'"
	    }
	    BREAK;
	DEFAULT:
	    AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnParseSetProperty(',acPropertyString,') unhandled'")
	    BREAK;
    }
}
	DEFINE_FUNCTION INTEGER fnSetPropertyHostname(CHAR acHostname[])
{
    INTEGER nResult

    IF(LENGTH_STRING(acHostname) > 0 && LENGTH_STRING(acHostname) <= MAX_HOSTNAME_LENGTH) {
	// what character would be allowed in a hostname????
	IF(FIND_STRING(acHostname,' ', 1)) {
	    // no spaces allowed in hostname
	    nResult = 2
	    AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnSetPropertyHostname(',acHostname,') invalid hostname: can`t contain spaces'")
	}
	ELSE {
	    // store ip adress
	    uIpDevice.acHostname = acHostname
	    
	    // reinit connection with new ip address
	    IF([vdvVirtual, DEVICE_COMMUNICATING] == TRUE) {
		AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnSetPropertyHostname(',acHostname,') changed, action:`performing required reinitialization`'")
		IP_CLIENT_CLOSE(dvDevice.PORT)
	    }
	}
    }
    ELSE {
	// length boundary invalid
	nResult = 1
	AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnSetPropertyHostname(',acHostname,') invalid length'")
    }
    
    RETURN nResult
}
	DEFINE_FUNCTION INTEGER fnSetPropertyIpAddress(CHAR acIpAddress[])
{
    INTEGER nResult
    INTEGER nIdx
    INTEGER nField[4]
    CHAR acNewIpAddress[MAX_IPADDRESS_LENGTH]

    acNewIpAddress = acIpAddress
    IF(LENGTH_STRING(acIpAddress) > 0) {
	IF(FIND_STRING(acIpAddress,'.',1)) {
	    nField[1] = ATOI(REMOVE_STRING(acIpAddress,'.',1))
	    IF(FIND_STRING(acIpAddress,'.',1)) {
		nField[2] = ATOI(REMOVE_STRING(acIpAddress,'.',1))
		IF(FIND_STRING(acIpAddress,'.',1)) {
		    nField[3] = ATOI(REMOVE_STRING(acIpAddress,'.',1))
		    nField[4] = ATOI(acIpAddress)
		}
	    }
	}
	
	FOR(nIdx = 1; nIdx <= 4; nIdx++) {
	    IF(nField[nIdx] > 254) {
		BREAK;
	    }
	}
	
	IF(nIdx == 5) {
	    // store ip adress
	    uIpDevice.acIpAddress = acNewIpAddress
	    
	    // reinit connection with new ip address
	    IF([vdvVirtual, DEVICE_COMMUNICATING] == TRUE) {
		AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnSetPropertyIpAddress(',acNewIpAddress,') changed, action:`performing required reinitialization`'")
		IP_CLIENT_CLOSE(dvDevice.PORT)
	    }
	}
	ELSE {
	    // one or more fields not within limits
	    AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnSetPropertyIpAddress(',acNewIpAddress,') one or more fields not within limits'")
	    nResult = 2
	}
    }
    ELSE {
	// no length
	AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnSetPropertyIpAddress(',acNewIpAddress,') invalid length'")
	nResult = 1
    }
    
    RETURN nResult
}
	DEFINE_FUNCTION INTEGER fnSetPropertyIpPort(CHAR acIpPort[])
{
    INTEGER nValue
    INTEGER nResult

    nValue = ATOI(acIpPort)
    IF(nValue >= 100 && nValue <= 100000) {
	// store ip port
	uIpDevice.nIpPort = ATOI(acIpPort)
	
	// reinit connection with new ip port
	IF([vdvVirtual, DEVICE_COMMUNICATING] == TRUE) {
	    AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnSetPropertyIpPort(',acIpPort,') changed, action:`performing required reinitialization`'")
	    IP_CLIENT_CLOSE(dvDevice.PORT)
	}
    }
    ELSE {
	// port number out of bounds
	AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnSetPropertyIpPort(',acIpPort,') port number out of bounds'")
	nResult = 1
    }
    
    RETURN nResult
}
	DEFINE_FUNCTION INTEGER fnSetPropertyUsername(CHAR acUsername[])
{
    INTEGER nResult

    IF(LENGTH_STRING(acUsername) < 64) {
	// store username
	uUser.acUsername = acUsername
	
	// reinit connection with new ip port
	IF([vdvVirtual, DEVICE_COMMUNICATING] == TRUE) {
	    AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnSetPropertyUsername(',acUsername,') changed, action:`performing required reinitialization`'")
	    IP_CLIENT_CLOSE(dvDevice.PORT)
	}
    }
    ELSE {
	// invalid username length
	AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnSetPropertyUsername(',acUsername,') invalid username length'")
	nResult = 1
    }
    
    RETURN nResult
}
	DEFINE_FUNCTION INTEGER fnSetPropertyPassword(CHAR acPassword[])
{
    INTEGER nResult

    IF(LENGTH_STRING(acPassword) < 64) {
	// store username
	uUser.acPassword = acPassword
	
	// reinit connection with new ip port
	IF([vdvVirtual, DEVICE_COMMUNICATING] == TRUE) {
	    AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnSetPropertyPassword(',acPassword,') changed, action:`performing required reinitialization`'")
	    IP_CLIENT_CLOSE(dvDevice.PORT)
	}
    }
    ELSE {
	// invalid password length
	AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnSetPropertyUsername(',acPassword,') invalid password length'")
	nResult = 1
    }
    
    RETURN nResult
}
	DEFINE_FUNCTION INTEGER fnSetPropertyPollInterval(CHAR acPollInterval[])
{
    INTEGER nValue
    INTEGER nResult

    nValue = ATOI(acPollInterval)
    IF(nValue >= 100 && nValue <= 10000) {
	lTimeArray[1] = nValue
	AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnSetPropertyPollInterval(',acPollInterval,') changed, action:`performing required timeline reload`'")
	TIMELINE_RELOAD(TIMELINE_ID_1, lTimeArray, LENGTH_ARRAY(lTimeArray))
    }
    ELSE {
	// pollinterval out of bounds
	nResult = 1
	AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnSetPropertyPollInterval(',acPollInterval,') pollinterval out of bounds'")
    }
    
    RETURN nResult
}
    DEFINE_FUNCTION fnParseGetProperty(CHAR acPropertyString[])
{
    CHAR acPropertyName[MAX_PROPNAME_LENGTH]
    CHAR acPropertyValue[MAX_PROPVAL_LENGTH]
    INTEGER nIdx
    
    acPropertyName = REMOVE_STRING(acPropertyString,':', 1)
    SET_LENGTH_STRING(acPropertyName, LENGTH_STRING(acPropertyName)-1)
    acPropertyName = LOWER_STRING(acPropertyName)
    acPropertyValue = acPropertyString
    
    FOR(nIdx = 1; nIdx <= LENGTH_ARRAY(acProperties); nIdx++) {
	IF(acProperties[nIdx] == acPropertyName) {
	    BREAK;
	}
    }
    
    SWITCH(nIdx) {
	CASE PROPERTY_HOSTNAME:
	    SEND_STRING vdvVirtual,"'PROPERTY-',acPropertyName,':',uIpDevice.acHostname"
	    BREAK;
	CASE PROPERTY_IPADDRESS:
	    SEND_STRING vdvVirtual,"'PROPERTY-',acPropertyName,':',uIpDevice.acIpAddress"
	    BREAK;
	CASE PROPERTY_IPPORT:
	    SEND_STRING vdvVirtual,"'PROPERTY-',acPropertyName,':',ITOA(uIpDevice.nIpPort)"
	    BREAK;
	CASE PROPERTY_USERNAME:
	    SEND_STRING vdvVirtual,"'PROPERTY-',acPropertyName,':',uUser.acUsername"
	    BREAK;
	CASE PROPERTY_PASSWORD:
	    SEND_STRING vdvVirtual,"'PROPERTY-',acPropertyName,':',uUser.acPassword"
	    BREAK;
	CASE PROPERTY_POLLINTERVAL:
	    SEND_STRING vdvVirtual,"'PROPERTY-',acPropertyName,':',ITOA(lTimeArray[1])"
	    BREAK;
	DEFAULT:
	    AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': fnParseGetProperty(',acPropertyString,') unhandled'")
	    BREAK;
    }
}
    DEFINE_FUNCTION fnParseSetLogLevel(CHAR acSetLogLevel[])
{
    INTEGER nIdx
    
    acSetLogLevel = LOWER_STRING(acSetLogLevel)
    FOR(nIdx = 1; nIdx <= LENGTH_ARRAY(acLogLevels); nIdx++) {
	IF(acLogLevels[nIdx] == acSetLogLevel) {
	    BREAK;
	}
    }
    
    IF(nIdx <= LENGTH_ARRAY(acLogLevels)) {
	SWITCH(nIdx) {
	    CASE AMX_ERROR:
	    CASE AMX_WARNING:
	    CASE AMX_INFO:
	    CASE AMX_DEBUG:
		SET_LOG_LEVEL(nIdx)
		BREAK;
	}
    }
    ELSE {
	AMX_LOG(AMX_ERROR,"'unsupported log level type: ', acSetLogLevel")
    }
}
    DEFINE_FUNCTION fnParseGetLogLevel()
{
    SEND_STRING vdvVirtual,"'LOG-',acLogLevels[GET_LOG_LEVEL()]"
}
    DEFINE_FUNCTION fnParseSqlQueryUse(CHAR acUseQuery[])
{
    fnAddTxBuffer("'use ',acUseQuery")
}
    DEFINE_FUNCTION fnParseSqlQueryCreate(CHAR acCreateQuery[])
{
    fnAddTxBuffer("'create ',acCreateQuery")
}
    DEFINE_FUNCTION fnParseSqlQueryAlter(CHAR acAlterQuery[])
{
    fnAddTxBuffer("'alter ',acAlterQuery")
}
    DEFINE_FUNCTION fnParseSqlQueryDrop(CHAR acDropQuery[])
{
    fnAddTxBuffer("'drop ',acDropQuery")
}
    DEFINE_FUNCTION fnParseSqlQueryInsert(CHAR acInsertQuery[])
{
    fnAddTxBuffer("'insert ',acInsertQuery")
}
    DEFINE_FUNCTION fnParseSqlQueryUpdate(CHAR acUpdateQuery[])
{
    fnAddTxBuffer("'update ',acUpdateQuery")
}
    DEFINE_FUNCTION fnParseSqlQueryDelete(CHAR acDeleteQuery[])
{
    fnAddTxBuffer("'delete ',acDeleteQuery")
}
    DEFINE_FUNCTION fnParseSqlQueryGrant(CHAR acGrantQuery[])
{
    fnAddTxBuffer("'grant ',acGrantQuery")
}
    DEFINE_FUNCTION fnParseSqlQueryRevoke(CHAR acRevokeQuery[])
{
    fnAddTxBuffer("'revoke ',acRevokeQuery")
}
    DEFINE_FUNCTION fnParseSqlQuerySelect(CHAR acSelectQuery[])
{
    fnAddTxBuffer("'select ',acSelectQuery")
}
DEFINE_FUNCTION fnParseResponse(CHAR acResponse[])
{
    INTEGER nIdx
    INTEGER nRowIdx
    CHAR acSubPacket[256]
    INTEGER nColumnIdx
    CHAR cAffectedRows
    CHAR acServerStatus[2]
    CHAR acWarnings[2]
    CHAR acErrorCode[2]
    INTEGER nErrorCode
    
    fnShowData("'rx(',ITOA(LENGTH_STRING(acResponse)),') ',acResponse")
    acPacketLength = GET_BUFFER_STRING(acResponse, 3)
    nPacketNumber = GET_BUFFER_CHAR(acResponse)
    nPacketLength = TYPE_CAST(acPacketLength[1] + acPacketLength[2]*256 + acPacketLength[3]*65536)
    
    IF(nPacketLength != LENGTH_STRING(acResponse)) {
	nNumberOfFields = GET_BUFFER_CHAR(acResponse)
	FOR(nIdx = 1, nColumnIdx = 1, nRowIdx = 1; nIdx <= 20; nIdx++) {
	    IF(LENGTH_STRING(acResponse) > 0) {
		acPacketLength = GET_BUFFER_STRING(acResponse, 3)
		nPacketNumber = GET_BUFFER_CHAR(acResponse)
		nPacketLength = TYPE_CAST(acPacketLength[1] + acPacketLength[2]*256 + acPacketLength[3]*65536)
		
		IF(nPacketLength <= 256) {
		    acSubPacket = GET_BUFFER_STRING(acResponse,nPacketLength)
		    IF(nColumnIdx <= nNumberOfFields) {
			// get columnName
			acColumns[nColumnIdx] = fnGetColumnName(acSubPacket)
			nColumnIdx++
		    }
		    ELSE {
			//EOF or Row info?
			IF(acSubPacket[1] == $FE) {
			    // EOF so.... what?
			}
			ELSE {
			    // this should be row data
			    fnShowData("'EOF or Row? ',acSubPacket")
			    acRows[nRowIdx] = fnGetRowInfo(acSubPacket)
			    nRowIdx++
			}
		    }
		}
	    }
	    ELSE {
		BREAK;
	    }
	}
	
	// now what?
	FOR(nIdx = 1; nIdx < nRowIdx; nIdx++) {
	    SEND_STRING vdvVirtual,"ITOA(nIdx),':',acRows[nIdx]"
	}
    }
    ELSE {
	cStatus = GET_BUFFER_CHAR(acResponse)
	
	SWITCH(cStatus) {
	    CASE $00: // OK
		SWITCH(eCommState) {
		    CASE eSTATE_START:
			// login was succesfull
			nAttempt = 0
			AMX_LOG(AMX_INFO,"'login was succesfull'")
			SEND_STRING vdvVirtual,"'LOGIN OK'"
			eCommState++
			AMX_LOG(AMX_DEBUG,"'eCommState: ', ITOA(eCommState)")
		    DEFAULT:
			cAffectedRows = GET_BUFFER_CHAR(acResponse)
			acServerStatus = GET_BUFFER_STRING(acResponse,2)
			acWarnings = GET_BUFFER_STRING(acResponse,2)
			AMX_LOG(AMX_DEBUG,'   OK')
			SEND_STRING vdvVirtual,"'OK'"
			BREAK;
		}
		BREAK;
	    CASE $FE: // EOF
		AMX_LOG(AMX_DEBUG,'   EOF')
		BREAK;
	    CASE $FF: // ERROR
		acErrorCode = GET_BUFFER_STRING(acResponse,2)
		nErrorCode = acErrorCode[1] + acErrorCode[2]*256
		AMX_LOG(AMX_ERROR,"'   ERROR(',ITOA(nErrorCode),') ',acResponse")
		SEND_STRING vdvVirtual,"'ERROR=',ITOA(nErrorCode),' ',acResponse"
		
		SWITCH(nErrorCode) {
		    CASE 1045:
			IF(acLoginState == 'attempting') {
			    nAttempt++
			    AMX_LOG(AMX_ERROR,"'   nAttempt(',ITOA(nAttempt),')'")
			}
			BREAK;
		    DEFAULT:
			BREAK;
		}
		BREAK;
	    DEFAULT:
		IF(nPacketNumber == 0) {
		    // Assume it's a server greeting???
		    fnParseServerGreeting(cStatus,acResponse)
		    acLoginState = 'attempting'
		    fnDoSQLLoginDynamic()
		}
		ELSE {
		    AMX_LOG(AMX_ERROR,'   UNHANDLED')
		}
		BREAK;
	}
    }
}
    DEFINE_FUNCTION fnParseServerGreeting(CHAR cProtocolVersion, CHAR acResponse[])
{
    STACK_VAR CHAR cDataByte1
    STACK_VAR CHAR cDataByte2
    STACK_VAR CHAR cDataByte3
    STACK_VAR CHAR cDataByte4

    // server version
    uServerGreeting.acServerVersion = GET_BUFFER_STRING(acResponse, FIND_STRING(acResponse,"$00",1))
    AMX_LOG(AMX_DEBUG,"'acServerVersion: ', uServerGreeting.acServerVersion")
    
    // thread id
    cDataByte1 = GET_BUFFER_CHAR(acResponse)
    cDataByte2 = GET_BUFFER_CHAR(acResponse)
    cDataByte3 = GET_BUFFER_CHAR(acResponse)
    cDataByte4 = GET_BUFFER_CHAR(acResponse)
    uServerGreeting.nThreadID = TYPE_CAST(cDataByte1 + 256*cDataByte2 + 65535*cDataByte3 + 16777216*cDataByte4)
    AMX_LOG(AMX_DEBUG,"'nThreadID: ', ITOA(uServerGreeting.nThreadID)")

    // salt (scramble_buff)
    uServerGreeting.acSalt = GET_BUFFER_STRING(acResponse, 8)
    AMX_LOG(AMX_DEBUG,"'acSalt: ', uServerGreeting.acSalt")
    
    // filler, always 0x00
    GET_BUFFER_CHAR(acResponse)
    
    // server capabilities1
    cDataByte1 = GET_BUFFER_CHAR(acResponse)
    cDataByte2 = GET_BUFFER_CHAR(acResponse)
    uServerGreeting.lServerCapabilities1 = cDataByte1 + 256*cDataByte2
    AMX_LOG(AMX_DEBUG,"'lServerCapabilities1: ', ITOA(uServerGreeting.lServerCapabilities1)")

    // server language
    cDataByte1 = GET_BUFFER_CHAR(acResponse)
    uServerGreeting.nCharset = cDataByte1
    AMX_LOG(AMX_DEBUG,"'SQLServerLanguage: ', ITOA(uServerGreeting.nCharset)")

    // server status
    cDataByte1 = GET_BUFFER_CHAR(acResponse)
    cDataByte2 = GET_BUFFER_CHAR(acResponse)
    uServerGreeting.lServerStatus = cDataByte1 + 256*cDataByte2
    AMX_LOG(AMX_DEBUG,"'lServerStatus: ', ITOA(uServerGreeting.lServerStatus)")

    // server capabilities2
    cDataByte1 = GET_BUFFER_CHAR(acResponse)
    cDataByte2 = GET_BUFFER_CHAR(acResponse)
    uServerGreeting.lServerCapabilities2 = cDataByte1 + 256*cDataByte2
    AMX_LOG(AMX_DEBUG,"'lServerCapabilities2: ', ITOA(uServerGreeting.lServerCapabilities2)")

    // length of auth-plugin-data
    AMX_LOG(AMX_DEBUG,"'length of auth-plugin-data: ',  ITOA(GET_BUFFER_CHAR(acResponse))")

    // filler, unused
    uServerGreeting.acReserved = GET_BUFFER_STRING(acResponse, 10)
    
    // rest of scramble buff
    uServerGreeting.acSubSalt = GET_BUFFER_STRING(acResponse, 13)
    AMX_LOG(AMX_DEBUG,"'acSubSalt: ', uServerGreeting.acSubSalt")
    
//    uSHA1HMAC.acSalt = "uServerGreeting.acSalt, uServerGreeting.acSubSalt"
//    uSHA1HMAC.acPassword = uUser.acPassword
//    uSHA1HMAC.acHash = fnEncryptSHA1WithMySQLSalt(uUser.acPassword,uServerGreeting.acSalt)
// Dit is VERKEERD dit zou moeten zijn|:  MySQLSalt(uUser.acPassword,uSHA1HMAC.acSalt)  
    uSHA1HMAC.acSalt = "uServerGreeting.acSalt, uServerGreeting.acSubSalt"
    uSHA1HMAC.acPassword = uUser.acPassword
    uSHA1HMAC.acHash = fnEncryptSHA1WithMySQLSalt(uUser.acPassword,uSHA1HMAC.acSalt)

    // payload
    uServerGreeting.acAuthPluginName = GET_BUFFER_STRING(acResponse, FIND_STRING(acResponse,"$00",1))
    AMX_LOG(AMX_DEBUG,"'auth-plugin name: ', uServerGreeting.acAuthPluginName")
}
    DEFINE_FUNCTION fnDoSQLLoginDynamic()
{
    CHAR acString[100]
    INTEGER nLength
    
    acString = "$00,$00,$00"				// packet length
    acString = "acString,$01"				// packet number
    acString = "acString, acClientCapabilities"		// client capabilities
    acString = "acString, acExtClientCapabilities"	// extended client capabilities
    acString = "acString, acMaxPacketBytes"		// max packet bytes
    acString = "acString, cCharSet,acNullFiller"	// character set
    acString = "acString, uUser.acUsername,$00"		// null terminated username

    IF(nAttempt > 0) { // first attempt wihtout pwd
	acString = "acString, $14"			// password length
	acString = "acString, uSHA1HMAC.acHash"		// null terminated hashed_password
	AMX_LOG(AMX_INFO,"'login salt    : ', uServerGreeting.acSalt,uServerGreeting.acSubSalt")
	AMX_LOG(AMX_INFO,"'login password: ', uUser.acPassword")
	AMX_LOG(AMX_INFO,"'login hash    : ', uSHA1HMAC.acHash")
    }
    ELSE {
	acString = "acString, $00"			// password length
    }
    acString = "acString, 'mysql_native_password',$00"	// null terminated native_password

    nLength = LENGTH_STRING(acString)
    acString[1] = TYPE_CAST(nLength - 4)
    SET_LENGTH_STRING(acString, nLength)
    
    fnShowData("'tx(',ITOA(LENGTH_STRING(acString)),') ',acString")
    SEND_STRING dvDevice,"acString"
}
    DEFINE_FUNCTION CHAR[32] fnGetColumnName(CHAR acData[])
{
    INTEGER nLength
    INTEGER nItemIdx
    CHAR acColumnName[MAX_COLUMNNAME_LENGTH]
    
    FOR(nItemIdx = 1; nItemIdx <= LENGTH_ARRAY(acItems); nItemIdx++) {
	IF(LENGTH_STRING(acData) > 0) {
	    nLength = GET_BUFFER_CHAR(acData)
	    acItems[nItemIdx]  = GET_BUFFER_STRING(acData,nLength)
	    fnShowData("'item ', acItems[nItemIdx]")
	}
	ELSE {
	    // no more data to parse
	    BREAK;
	}
    }
    
    acColumnName = acItems[5]
    fnShowData("'column ', acColumnName")
    
    RETURN acColumnName
}
    DEFINE_FUNCTION CHAR[100] fnGetRowInfo(CHAR acData[])
{
    INTEGER nLength
    CHAR acInfo[200]
    
    fnShowData("'row ', acData")
    
    nLength = GET_BUFFER_CHAR(acData)
    acInfo  = GET_BUFFER_STRING(acData,nLength)
    fnShowData("'row ', acInfo")
    
    nLength = GET_BUFFER_CHAR(acData)
    acInfo  = "acInfo,' ',GET_BUFFER_STRING(acData,nLength)"
    fnShowData("'row ', acInfo")

    nLength = GET_BUFFER_CHAR(acData)
    acInfo  = "acInfo,' ', GET_BUFFER_STRING(acData,nLength)"
    fnShowData("'row ', acInfo")
    
    RETURN acInfo
}
    DEFINE_FUNCTION fnShowData(CHAR acPrintLine[])
{
    INTEGER nIdx
    INTEGER nLength
    CHAR acLine[300]
    
    nLength =  LENGTH_STRING(acPrintLine)
    IF(nLength)
    {
	FOR(nIdx = 1; nIdx <= nLength; nIdx++) {
	    IF((acPrintLine[nIdx] >= $20) && (acPrintLine[nIdx] <= $7E)) {
		acLine = "acLine,acPrintLine[nIdx]"
	    }
	    ELSE {
		acLine = "acLine, '$',FORMAT('%02x', acPrintLine[nIdx])"
	    }
	    
	    // print out per 80 chars... (5*16bytes)
	    IF((nIdx % 80) == 0) {
		AMX_LOG(AMX_ERROR,"acLine")
		acLine = ''
	    }
	}
	
	AMX_LOG(AMX_ERROR,"acLine")
    }
    ELSE {
	AMX_LOG(AMX_ERROR,"'data has no length, unable to print'")
    }
}

DEFINE_FUNCTION fnSendSqlQuery(CHAR acData[])
{
    INTEGER nIdx
    CHAR acQuery[MAX_COMMAND_LENGTH]
    CHAR acString[MAX_COMMAND_LENGTH]
    
    SWITCH(acData[1]) {
	CASE COM_PING:
	    acQuery[1] = acData[1]
	    SET_LENGTH_STRING(acQuery, 1)
	    BREAK;
	DEFAULT:
	    acQuery = "COM_QUERY, acData"
	    SET_LENGTH_STRING(acQuery, LENGTH_STRING(acData)+1)
	    BREAK;
    }
    acString[1] = TYPE_CAST(LENGTH_STRING(acQuery) % 256)
    acString[2] = TYPE_CAST(LENGTH_STRING(acQuery) / 256)
    acString[3] = TYPE_CAST(LENGTH_STRING(acQuery) / 65536)
    acString[4]  = $00	// packet number
    
    FOR(nIdx = 1; nIdx <= LENGTH_STRING(acQuery); nIdx++) {
	acString[4+nIdx]  = acQuery[nIdx]
    }	
    SET_LENGTH_STRING(acString, 3+nIdx)
    
    nAwaitResponse = TRUE
    fnShowData("'tx ',acString")
    SEND_STRING dvDevice,"acString"
}

(***********************************************************)
(*                STARTUP CODE GOES BELOW                  *)
(***********************************************************)
DEFINE_START
TIMELINE_CREATE(TIMELINE_ID_1, lTimeArray, LENGTH_ARRAY(lTimeArray), TIMELINE_ABSOLUTE, TIMELINE_REPEAT)
CREATE_BUFFER dvDevice, acBuffer
nTxRead  = 1
nTxWrite = 1

(***********************************************************)
(*                THE EVENTS GO BELOW                      *)
(***********************************************************)
DEFINE_EVENT
DATA_EVENT[dvDevice]
{
    ONLINE:
    {
	AMX_LOG(AMX_DEBUG,"'mdl ',__FILE__,': ip connection established'")
    }
    STRING:
    {
	SWITCH(eCommState) {
	    CASE eSTATE_INACTIVE:
		// should never get here
		AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': string event: eCommState (',ITOA(eCommState),') unexpected'")
		BREAK;
	    CASE eSTATE_START:
		// response is server greeting
		fnParseResponse(DATA.TEXT)
		BREAK;
	    CASE eSTATE_IDLE:
		// normal routine handling
		fnParseResponse(DATA.TEXT)
		ON[vdvVirtual, DEVICE_COMMUNICATING]
		ON[vdvVirtual, DATA_INITIALIZED]
		nAwaitResponse = FALSE;
		BREAK;
	    DEFAULT:
		// should never get here
		AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': string event: eCommState (',ITOA(eCommState),') unexpected'")
		BREAK;
	}
	CLEAR_BUFFER acBuffer
    }
    ONERROR:
    {
	AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': ip error(',GET_IP_ERROR(DATA.NUMBER),')'")
	slIpConnection = TYPE_CAST(DATA.NUMBER)
    }
    OFFLINE:
    {
	slIpConnection = IP_STATUS_UNKNOWN
	OFF[vdvVirtual, DEVICE_COMMUNICATING]
	OFF[vdvVirtual, DATA_INITIALIZED]
	AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': ip connection dropped'")
    }
}

DATA_EVENT[vdvVirtual]
{
    ONLINE:
    {
	// start communications state machine
	WAIT 30 {
	    // wait some time to have module properties set
	    slIpConnection = IP_STATUS_UNKNOWN
	    eCommState = eSTATE_START
	    TIMELINE_CREATE(TIMELINE_ID_1, lTimeArray, LENGTH_ARRAY(lTimeArray), TIMELINE_ABSOLUTE, TIMELINE_REPEAT)
	}
    }
    COMMAND:
    {
	CHAR acCommand[MAX_COMMAND_LENGTH]
	INTEGER nIdx
	
	// get CMD
	IF(FIND_STRING(DATA.TEXT,'?',1)) {
	    acCommand = DATA.TEXT
	}
	ELSE IF(FIND_STRING(DATA.TEXT,'-',1)) {
	    acCommand = REMOVE_STRING(DATA.TEXT,'-',1)
	    SET_LENGTH_STRING(acCommand, LENGTH_STRING(acCommand)-1)
	}
	
	// lookup and execute
	FOR(nIdx = 1; nIdx <= LENGTH_ARRAY(acCommands); nIdx++) {
	    IF(COMPARE_STRING(acCommands[nIdx],"UPPER_STRING(acCommand)")) {
		fnParseCommand(nIdx, DATA.TEXT)
		BREAK;
	    }
	}
	
	IF(nIdx > LENGTH_ARRAY(acCommands)) {
	    AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': command (',acCommand,') unhandled'")
	}
    }
}

TIMELINE_EVENT[TIMELINE_ID_1]
{
    CHAR acTransmitCmd[MAX_COMMAND_LENGTH]
    
    acTransmitCmd = ''
    nTimeLineRepetition = TIMELINE.REPETITION
    SWITCH(TIMELINE.SEQUENCE) {
	CASE 1:
	    // sending stuff
	    SWITCH(eCommState) {
		CASE eSTATE_INACTIVE:
		    // should never get here
		    AMX_LOG(AMX_ERROR,"'mdl ',__FILE__,': timeline send_event: eCommState (',ITOA(eCommState),') unexpected'")
		    BREAK;
		CASE eSTATE_START:
		    // initialize ip communication
		    IF(LENGTH_STRING(uIpDevice.acHostname)) {
			acServerAddress = uIpDevice.acHostname
		    }
		    ELSE IF(LENGTH_STRING(uIpDevice.acIpAddress)) {
			acServerAddress = uIpDevice.acIpAddress
		    }
		    IF(LENGTH_STRING(acServerAddress) && uIpDevice.nIpPort > 0) {
			// validate ip address and port
			IF(slIpConnection) {
			    // only open if not already online and returned an error
			    IF(nAttempt <= 100) {
				// increase retry time with every attempt untill 100 attempts
				IF(!(nTimeLineRepetition % nAttempt)) {
				    slIpConnection = IP_CLIENT_OPEN(dvDevice.PORT, acServerAddress, uIpDevice.nIpPort, IP_TCP)
				}
			    }
			}
		    }
		    BREAK;
		CASE eSTATE_IDLE:
		    // check to send something
		    IF(nTxRead != nTxWrite) {
			AMX_LOG(AMX_DEBUG,"acCommandBuffer[nTxRead]")
			acTransmitCmd = acCommandBuffer[nTxRead]
			nTxRead = (nTxRead % MAX_BUFFER_COMMANDS) + 1
			fnSendSqlQuery(acTransmitCmd)
		    }
		    ELSE {
			IF(!(TIMELINE.REPETITION % 5)) {
			    acTransmitCmd = "COM_PING"
			    fnSendSqlQuery(acTransmitCmd)
			}
		    }
		    BREAK;
	    }
	    BREAK;
	CASE 2:
	    // timeout for receiving stuff
	    SWITCH(eCommState) {
		CASE eSTATE_INACTIVE:
		CASE eSTATE_START:
		    // for now, do nothing  on timeout
		    BREAK;
		CASE eSTATE_IDLE:
		    IF(nAwaitResponse == TRUE) {
			OFF[vdvVirtual, DEVICE_COMMUNICATING]
			OFF[vdvVirtual, DATA_INITIALIZED]
		    }
		    ELSE {
			// received response within a set period of time
		    }
		    BREAK;
	    }
	    BREAK;
    }
}

CHANNEL_EVENT[vdvVirtual, 0]
{
    ON:
    {
	SWITCH(CHANNEL.CHANNEL) {
	    CASE DEVICE_COMMUNICATING:
	    CASE DATA_INITIALIZED:
		eCommState = eSTATE_IDLE
		BREAK;
	    DEFAULT:
		// do nothing
		BREAK;
	}
    }
    OFF:
    {
	SWITCH(CHANNEL.CHANNEL) {
	    CASE DEVICE_COMMUNICATING:
		eCommState = eSTATE_START
		BREAK;
	    CASE DATA_INITIALIZED:
		// always followed by off event for DEVICE_COMMUNICATING
		// let DEVICE_COMMUNICATING handle this.
		BREAK;
	    DEFAULT:
		// do nothing
		BREAK;
	}
    }
}


(***********************************************************)
(*            THE ACTUAL PROGRAM GOES BELOW                *)
(***********************************************************)
DEFINE_PROGRAM

(***********************************************************)
(*                     END OF PROGRAM                      *)
(*        DO NOT PUT ANY CODE BELOW THIS COMMENT           *)
(***********************************************************)
