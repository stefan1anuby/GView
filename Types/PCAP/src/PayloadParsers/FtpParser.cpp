#include "FtpParser.hpp"

using namespace GView::Type::PCAP;


PayloadDataParserInterface* FTP::FTPParser::ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface)
{
    if (memcmp(payloadInformation.payload->location, "220 ", 4) != 0)
        // Failed to recognize it as FTP
        return nullptr;

    auto& applicationLayers = callbackInterface->GetApplicationLayers();
    bool isResponse         = true;
    bool insideMultiline    = false;
    std::string multilineCode;

    StreamTcpLayer layer                                         = {};
    Panels::FTP_PANEL_SUMMARY_LINES_TYPE* layerSummaryPanelLines = new std::vector<std::string>();
    for (auto& packet : *payloadInformation.packets) {
        // Skip empty payloads
        if (packet.payload.size == 0)
            continue;
        if (packet.payload.size >= 3 && isdigit(packet.payload.location[0]) && isdigit(packet.payload.location[1]) && isdigit(packet.payload.location[2]))
            isResponse = true;
        // Determine prefix based on isResponse and compute lengths
        const char* prefixCStr = isResponse ? "Response: " : "Request: ";
        const size_t prefixLen = strlen(prefixCStr);

        // Preserve previous behavior of trimming last 2 bytes (likely CRLF), but ensure no underflow
        size_t payloadLen = 0;
        if (packet.payload.size > 2)
            payloadLen = static_cast<size_t>(packet.payload.size - 2);

        // Allocate space for prefix + payload + null terminator
        size_t totalLen = prefixLen + payloadLen + 1;
        layer.name      = std::make_unique<uint8[]>(totalLen);

        // Copy prefix
        memcpy(layer.name.get(), prefixCStr, prefixLen);

        if (payloadLen > 0) {
            // Copy payload content (as bytes) after the prefix
            memcpy(layer.name.get() + prefixLen, packet.payload.location, payloadLen);

            // Set the layer payload
            layer.payload.location = packet.payload.location;
            layer.payload.size     = static_cast<uint32>(payloadLen);
        }

        std::string line(reinterpret_cast<char*>(layer.name.get()));

        bool isRequest = line.rfind("Request: ", 0) == 0;
        if (isRequest) {
            std::string cmdLine = line.substr(9); // remove "Request: "
            HandleCommand(cmdLine, *layerSummaryPanelLines);
        } else {
            std::string cmdLine = line.substr(10); // remove "Response: "

            // --- ADD MULTILINE RESPONSE HANDLING ---
            std::string code = cmdLine.substr(0, 3);
            if (!insideMultiline) {
                if (cmdLine.size() > 3 && cmdLine[3] == '-') {
                    insideMultiline = true;
                    multilineCode   = code;
                    std::string searchFor = multilineCode + " End";
                    // check if same line already has END
                    if (cmdLine.find(searchFor) != std::string::npos)
                        insideMultiline = false;
                }
            } else {
                std::string searchFor = multilineCode + " End";
                // we are inside multiline, check for END
                if (cmdLine.find(searchFor) != std::string::npos)
                    insideMultiline = false;
            }

            HandleResponse(cmdLine, *layerSummaryPanelLines);
        }

        // Null-terminate
        layer.name.get()[prefixLen + payloadLen] = 0;

        applicationLayers.emplace_back(std::move(layer));
        layer.Clear();

        // Toggle for next packet only if we are not inside a multiline response
        if (!insideMultiline)
            isResponse = !isResponse;
    }

    pfile.layerSummaryString.push_back(layerSummaryPanelLines);

    callbackInterface->AddConnectionSummary("parsed application stream layers");
    callbackInterface->AddConnectionAppLayerName("FTP");
    return this;
}

void HandleUSER(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    s.user.username     = arg;
    s.expectingPassword = true;
    layerSummaryPanelLines.push_back("User " + arg + " tried to log in");
}

void HandlePASS(const std::string&, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    if (!s.expectingPassword)
        layerSummaryPanelLines.push_back("Password entered without username");
    else
        layerSummaryPanelLines.push_back("User " + s.user.username + " logged in successfully");

    s.user.isLoggedIn   = true;
    s.expectingPassword = false;
}

void HandleACCT(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " provided account information");
}

void HandleCWD(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    if (!s.user.isLoggedIn)
        layerSummaryPanelLines.push_back("User " + s.user.username + " tried to change directory before logging in");
    else
        layerSummaryPanelLines.push_back("User " + s.user.username + " changed working directory to " + arg);

    s.user.cwd = arg;
}

void HandleCDUP(GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    s.user.cwd = "/";
    layerSummaryPanelLines.push_back("User " + s.user.username + " moved to parent directory");
}

void HandleSMNT(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " mounted " + arg);
}

void HandleREIN(GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    s = GView::Type::PCAP::FTP::FtpSession{};
    layerSummaryPanelLines.push_back("User session reset");
}

void HandleQUIT(GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " logged out");
    s = GView::Type::PCAP::FTP::FtpSession{};
}
void HandlePORT(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    s.dataConnection.mode    = "active";
    s.dataConnection.address = arg;
    layerSummaryPanelLines.push_back("User " + s.user.username + " told the server to connect back for data transfer at " + arg);
}

void HandlePASV(GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    s.dataConnection.mode = "passive";
    layerSummaryPanelLines.push_back("User " + s.user.username + " asked the server to open a port for data transfer (passive mode)");
}

void HandleMODE(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    s.transfer.mode = arg;
    layerSummaryPanelLines.push_back("Transfer mode set to " + arg + " (controls how the data stream is sent)");
}

void HandleTYPE(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    s.transfer.type = arg;

    if (arg == "I")
        layerSummaryPanelLines.push_back("Transfer type set to I (binary mode, file sent exactly as-is)");
    else if (arg == "A")
        layerSummaryPanelLines.push_back("Transfer type set to A (text mode, line endings may be converted)");
    else
        layerSummaryPanelLines.push_back("Transfer type set to " + arg);
}

void HandleSTRU(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    s.transfer.structure = arg;
    layerSummaryPanelLines.push_back("Transfer structure set to " + arg + " (how the file is internally organized)");
}

void HandleALLO(const std::string& arg, GView::Type::PCAP::FTP::FtpSession&, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("Client reserved " + arg + " bytes on the server for the upcoming transfer");
}

void HandleREST(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    s.transfer.restartOffset = arg;
    layerSummaryPanelLines.push_back("Transfer will resume from byte offset " + arg);
}

void HandleSTOR(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " is uploading file: " + arg);
}

void HandleSTOU(GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " is uploading a file with a server-generated name");
}

void HandleRETR(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " is downloading file: " + arg);
}

void HandleLIST(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " requested a detailed directory listing of " + arg);
}

void HandleNLIST(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " requested a simple list of files in " + arg);
}

void HandleRNFR(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    s.transfer.renameFrom = arg;
    layerSummaryPanelLines.push_back("User " + s.user.username + " wants to rename the file: " + arg);
}

void HandleRNTO(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " renamed the file to: " + arg);
}

void HandleDELE(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " deleted the file: " + arg);
}

void HandleRMD(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " removed the directory: " + arg);
}

void HandleMKD(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " created a new directory: " + arg);
}

void HandlePWD(GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("Server reports current working directory is: " + s.user.cwd);
}

void HandleABOR(GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " cancelled the current transfer");
}

void HandleSYST(GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " asked what operating system the server is running");
}

void HandleSTAT(GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " requested current server status");
}

void HandleHELP(GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("User " + s.user.username + " requested help information from the server");
}

void HandleSITE(const std::string& arg, GView::Type::PCAP::FTP::FtpSession&, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("Client executed a server-specific command: " + arg);
}

void HandleNOOP(GView::Type::PCAP::FTP::FtpSession&, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("Client sent a keep-alive message (no operation)");
}



void HandleFEAT(GView::Type::PCAP::FTP::FtpSession&, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("Client asked the server what features it supports");
}

void HandleCLNT(const std::string& arg, GView::Type::PCAP::FTP::FtpSession&, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("Client identified itself as: " + arg);
}

void HandleSIZE(const std::string& arg, GView::Type::PCAP::FTP::FtpSession&, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("Client requested the size of file: " + arg);
}

void HandleMDTM(const std::string& arg, GView::Type::PCAP::FTP::FtpSession&, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("Client requested last modification time of file: " + arg);
}

void HandleOPTS(const std::string& arg, GView::Type::PCAP::FTP::FtpSession&, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    layerSummaryPanelLines.push_back("Client negotiated transfer options: " + arg);
}

void HandleEPSV(GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    s.dataConnection.mode = "passive";
    layerSummaryPanelLines.push_back("User " + s.user.username + " requested extended passive mode (modern PASV, IPv6-safe)");
}

void HandleEPRT(const std::string& arg, GView::Type::PCAP::FTP::FtpSession& s, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    s.dataConnection.mode    = "active";
    s.dataConnection.address = arg;
    layerSummaryPanelLines.push_back("User " + s.user.username + " provided extended address for active data connection: " + arg);
}




void GView::Type::PCAP::FTP::FTPParser::HandleCommand(const std::string& line, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    static FtpSession session;

    std::istringstream iss(line);
    std::string cmd, arg;
    iss >> cmd;
    std::getline(iss, arg);
    if (!arg.empty() && arg[0] == ' ')
        arg.erase(0, 1);

    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::toupper);

    // Login / Logout commands
    if (cmd == "USER")
        HandleUSER(arg, session, layerSummaryPanelLines);
    else if (cmd == "PASS")
        HandlePASS(arg, session, layerSummaryPanelLines);
    else if (cmd == "ACCT")
        HandleACCT(arg, session, layerSummaryPanelLines);
    else if (cmd == "CWD")
        HandleCWD(arg, session, layerSummaryPanelLines);
    else if (cmd == "CDUP")
        HandleCDUP(session, layerSummaryPanelLines);
    else if (cmd == "SMNT")
        HandleSMNT(arg, session, layerSummaryPanelLines);
    else if (cmd == "REIN")
        HandleREIN(session, layerSummaryPanelLines);
    else if (cmd == "QUIT")
        HandleQUIT(session, layerSummaryPanelLines);

    // Transfer parameter commands
    else if (cmd == "PORT")
        HandlePORT(arg, session, layerSummaryPanelLines);
    else if (cmd == "PASV")
        HandlePASV(session, layerSummaryPanelLines);
    else if (cmd == "MODE")
        HandleMODE(arg, session, layerSummaryPanelLines);
    else if (cmd == "TYPE")
        HandleTYPE(arg, session, layerSummaryPanelLines);
    else if (cmd == "STRU")
        HandleSTRU(arg, session, layerSummaryPanelLines);

    // File action commands
    else if (cmd == "ALLO")
        HandleALLO(arg, session, layerSummaryPanelLines);
    else if (cmd == "REST")
        HandleREST(arg, session, layerSummaryPanelLines);
    else if (cmd == "STOR")
        HandleSTOR(arg, session, layerSummaryPanelLines);
    else if (cmd == "STOU")
        HandleSTOU(session, layerSummaryPanelLines);
    else if (cmd == "RETR")
        HandleRETR(arg, session, layerSummaryPanelLines);
    else if (cmd == "LIST")
        HandleLIST(arg, session, layerSummaryPanelLines);
    else if (cmd == "NLIST")
        HandleNLIST(arg, session, layerSummaryPanelLines);
    else if (cmd == "RNFR")
        HandleRNFR(arg, session, layerSummaryPanelLines);
    else if (cmd == "RNTO")
        HandleRNTO(arg, session, layerSummaryPanelLines);
    else if (cmd == "DELE")
        HandleDELE(arg, session, layerSummaryPanelLines);
    else if (cmd == "RMD")
        HandleRMD(arg, session, layerSummaryPanelLines);
    else if (cmd == "MKD")
        HandleMKD(arg, session, layerSummaryPanelLines);
    else if (cmd == "PWD")
        HandlePWD(session, layerSummaryPanelLines);
    else if (cmd == "ABOR")
        HandleABOR(session, layerSummaryPanelLines);

    // Informational commands
    else if (cmd == "SYST")
        HandleSYST(session, layerSummaryPanelLines);
    else if (cmd == "STAT")
        HandleSTAT(session, layerSummaryPanelLines);
    else if (cmd == "HELP")
        HandleHELP(session, layerSummaryPanelLines);

    // Miscellaneous commands
    else if (cmd == "SITE")
        HandleSITE(arg, session, layerSummaryPanelLines);
    else if (cmd == "NOOP")
        HandleNOOP(session, layerSummaryPanelLines);
    //Others I found
    else if (cmd == "FEAT")
        HandleFEAT(session, layerSummaryPanelLines);
    else if (cmd == "CLNT")
        HandleCLNT(arg, session, layerSummaryPanelLines);
    else if (cmd == "SIZE")
        HandleSIZE(arg, session, layerSummaryPanelLines);
    else if (cmd == "MDTM")
        HandleMDTM(arg, session, layerSummaryPanelLines);
    else if (cmd == "OPTS")
        HandleOPTS(arg, session, layerSummaryPanelLines);
    else if (cmd == "EPSV")
        HandleEPSV(session, layerSummaryPanelLines);
    else if (cmd == "EPRT")
        HandleEPRT(arg, session, layerSummaryPanelLines);
  
    // Unknown commands
    else
        layerSummaryPanelLines.push_back("Unknown FTP command: " + cmd);
}
void GView::Type::PCAP::FTP::FTPParser::HandleResponse(const std::string& line, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines)
{
    std::istringstream iss(line);
    std::string code;
    iss >> code;

    std::string rest;
    std::getline(iss, rest);
    if (!rest.empty() && rest[0] == ' ')
        rest.erase(0, 1);

    if (code == "220")
        layerSummaryPanelLines.push_back("Server is ready to accept connections");
    else if (code == "230")
        layerSummaryPanelLines.push_back("Login successful");
    else if (code == "215")
        layerSummaryPanelLines.push_back("Server reports operating system: " + rest);
    else if (code == "226")
        layerSummaryPanelLines.push_back("File transfer finished successfully");
    else if (code == "150")
        layerSummaryPanelLines.push_back("File transfer starting");
    else if (code == "213")
        layerSummaryPanelLines.push_back("Server returned file information: " + rest);
    else if (code == "229")
        layerSummaryPanelLines.push_back("Server opened a passive data port");
    else if (code == "331")
        layerSummaryPanelLines.push_back("Server asks for password");
    else if (code == "257")
        layerSummaryPanelLines.push_back("Server reports current directory: " + rest);
    else if (code == "211")
        layerSummaryPanelLines.push_back("Server provided capability or status information");
    else if (code == "257")
        layerSummaryPanelLines.push_back("Server reports current directory: " + rest);
    else if (code == "229")
        layerSummaryPanelLines.push_back("Server selected a port for passive data connection");
    else if (code == "150")
        layerSummaryPanelLines.push_back("Server is about to start transferring data");
    else if (code == "226")
        layerSummaryPanelLines.push_back("Server finished transferring data");
    else if (code == "213")
        layerSummaryPanelLines.push_back("Server returned file metadata: " + rest);
    else if (code == "250")
        layerSummaryPanelLines.push_back("Requested action completed successfully");
    else if (code == "221")
        layerSummaryPanelLines.push_back("Server closed the connection");

    else
        layerSummaryPanelLines.push_back("Server reply: " + line);
}
