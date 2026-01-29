#include "FtpParser.hpp"

using namespace GView::Type::PCAP;


PayloadDataParserInterface* FTP::FTPParser::ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface)
{
    if (memcmp(payloadInformation.payload->location, "220 ", 4) != 0)
        // Failed to recognize it as FTP
        return nullptr;

    auto& applicationLayers = callbackInterface->GetApplicationLayers();
    bool isResponse         = true;

    StreamTcpLayer layer = {};
    Panels::FTP_PANEL_SUMMARY_LINES_TYPE* layerSummaryPanelLines = new std::vector<std::string>();
    for (auto& packet : *payloadInformation.packets)
    {
        // Skip empty payloads
        if (packet.payload.size == 0)
            continue;

        // Determine prefix based on isResponse and compute lengths
        const char* prefixCStr = isResponse ? "Response: " : "Request: ";
        const size_t prefixLen = strlen(prefixCStr);

        // Preserve previous behavior of trimming last 2 bytes (likely CRLF), but ensure no underflow
        size_t payloadLen = 0;
        if (packet.payload.size > 2)
            payloadLen = static_cast<size_t>(packet.payload.size - 2);

        // Allocate space for prefix + payload + null terminator
        size_t totalLen = prefixLen + payloadLen + 1;
        layer.name = std::make_unique<uint8[]>(totalLen);

        // Copy prefix
        memcpy(layer.name.get(), prefixCStr, prefixLen);

        if (payloadLen > 0)
        {
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
        }


        // Null-terminate
        layer.name.get()[prefixLen + payloadLen] = 0;

        applicationLayers.emplace_back(std::move(layer));
        layer.Clear();

        // Toggle for next packet
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
}


