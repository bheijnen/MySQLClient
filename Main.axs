PROGRAM_NAME='Main'
(***********************************************************)
(***********************************************************)
(*  FILE_LAST_MODIFIED_ON: 04/05/2006  AT: 09:00:25        *)
(***********************************************************)
(* System Type : NetLinx                                   *)
(***********************************************************)
(* REV HISTORY:                                            *)
(***********************************************************)
(*
    $History: $
*)
(***********************************************************)
(*          DEVICE NUMBER DEFINITIONS GO BELOW             *)
(***********************************************************)
DEFINE_DEVICE
dvMySQLServer	=	    0: 3:0
dvSerialTest	=	 5001: 1:0
dvIODeurbel	=	 5001:17:0
vdvMySQLServer	=	33001: 1:0

(***********************************************************)
(*               CONSTANT DEFINITIONS GO BELOW             *)
(***********************************************************)
DEFINE_CONSTANT

(***********************************************************)
(*              DATA TYPE DEFINITIONS GO BELOW             *)
(***********************************************************)
DEFINE_TYPE

(***********************************************************)
(*               VARIABLE DEFINITIONS GO BELOW             *)
(***********************************************************)
DEFINE_VARIABLE

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
DEFINE_FUNCTION fnShowData(CHAR acPrintLine[])
{
    INTEGER nIdx
    INTEGER nLength
    CHAR acLine[300]
    
    nLength =  LENGTH_STRING(acPrintLine)
    IF(nLength)
    {
	FOR(nIdx = 1; nIdx <= nLength; nIdx++) {
	    //acLine = "acLine, FORMAT('%02x', acPrintLine[nIdx])"
	    acLine = "acLine, acPrintLine[nIdx]"
	    
	    // print out per 118 chars...
	    IF((nIdx % 118) == 0) {
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

DEFINE_FUNCTION CHAR[20] DATE_TIME()
{
    CHAR acDateTime[20]
    
    //2014-01-06 15:53:16
    RETURN "ITOA(DATE_TO_YEAR(LDATE)),'-',FORMAT('%02d',DATE_TO_MONTH(LDATE)),'-',FORMAT('%02d',DATE_TO_DAY(LDATE)),' ',TIME"
}

DEFINE_MODULE 'mdlMySQLClient_Comm' MySQL_Comm(vdvMySQLServer, dvMySQLServer)

(***********************************************************)
(*                STARTUP CODE GOES BELOW                  *)
(***********************************************************)
DEFINE_START

(***********************************************************)
(*                THE EVENTS GO BELOW                      *)
(***********************************************************)
DEFINE_EVENT
DATA_EVENT[vdvMySQLServer]
{
    ONLINE:
    {
	SEND_COMMAND DATA.DEVICE,"'LOG-DEBUG'"
	SEND_COMMAND DATA.DEVICE,"'PROPERTY-Username:bheijnen'"
	SEND_COMMAND DATA.DEVICE,"'PROPERTY-Password:brianh'"
	SEND_COMMAND DATA.DEVICE,"'PROPERTY-HostName:brianheijnen.myqnapcloud.com'"
	SEND_COMMAND DATA.DEVICE,"'PROPERTY-IpPort:3306'"
    }
    STRING:
    {
	fnShowData(DATA.TEXT)
    }
    OFFLINE:
    {
    /*
	SEND_COMMAND DATA.DEVICE,"'USE-test'"
	SEND_COMMAND DATA.DEVICE,"'SELECT-* from Persons'"
	SEND_COMMAND DATA.DEVICE,"'INSERT-into Persons (`FirstName`,`LastName`,`Address`) VALUES (',$27,'b',$27,',',$27,'h',$27,',',$27,'silo 16',$27,');'"
	SEND_COMMAND DATA.DEVICE,"'DELETE-from Persons where Address=',$27,'silo 16',$27"
	SEND_COMMAND DATA.DEVICE,"'PASSTHRU-use test'"
	SEND_COMMAND DATA.DEVICE,"'PASSTHRU-select * from Persons'"
	SEND_COMMAND DATA.DEVICE,"'PASSTHRU-select * from Persons where LastName=',$27,'sab',$27"
	SEND_COMMAND DATA.DEVICE,"'PASSTHRU-select * from Persons where FirstName=',$27,'bas',$27"
	SEND_COMMAND DATA.DEVICE,"'PASSTHRU-INSERT INTO Persons (`FirstName`,`LastName`,`Address`) VALUES (',$27,'b',$27,',',$27,'c',$27,',',$27,'dstraat 33',$27,');'"
	SEND_COMMAND DATA.DEVICE,"'PASSTHRU-INSERT INTO Persons (`FirstName`,`LastName`,`Address`) VALUES (',$27,'bas',$27,',',$27,'sab',$27,',',$27,'kerkstraat 23',$27,');'"
	SEND_COMMAND DATA.DEVICE,"'PASSTHRU-INSERT INTO Persons (`FirstName`,`LastName`,`Address`) VALUES (',$27,'cas',$27,',',$27,'sab',$27,',',$27,'pleinstraat 32',$27,');'"
	SEND_COMMAND DATA.DEVICE,"''"
	SEND_COMMAND DATA.DEVICE,"'HASH-6;gv<ejd8)c8-x9Qi=3*'"
	SEND_COMMAND DATA.DEVICE,"'HASH-W>l(~cWk2W>n5W9W+njK'"
	SEND_COMMAND DATA.DEVICE,"'HASH-0$cFu<hxB}sGIv:Z9N[^'"
	SEND_COMMAND DATA.DEVICE,"'HASH-6U,v38]LEU\LJmhCQP~J'" 
    */
    }
}

CHANNEL_EVENT[dvIODeurbel, 1]
{
    ON:
    {
	SEND_COMMAND vdvMySQLServer,"'INSERT-INTO `netlinx`.`deurbel` (`idx`, `Datum`, `Status`) VALUES (',$27,'10',$27,', ',$27,DATE_TIME(),$27,', ',$27,'1',$27,');'"
    }
    OFF: 
    {
	SEND_COMMAND vdvMySQLServer,"'INSERT-INTO `netlinx`.`deurbel` (`idx`, `Datum`, `Status`) VALUES (',$27,'10',$27,', ',$27,DATE_TIME(),$27,', ',$27,'0',$27,');'"
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

