#pragma once

#include "API.hpp"
#include "PCAP.hpp"

namespace GView::Type::PCAP::Panels
{
class LayerSummary;
}

namespace GView::Type::PCAP::FTP
{
struct FtpUserState {
    bool isLoggedIn = false;
    std::string username;
    std::string cwd = "/";
};



struct FtpDataConnection {
    std::string mode;
    std::string address;
};
struct FtpTransfer {
    std::string type;
    std::string mode;
    std::string structure;
    std::string restartOffset;
    std::string renameFrom;
};
struct FtpSession {
    FtpUserState user;
    bool expectingPassword = false;

    FtpDataConnection dataConnection;
    FtpTransfer transfer;
};
struct FTPParser : public PayloadDataParserInterface {
    PCAPFile& pfile;
    FTPParser(PCAPFile& _pfile) : pfile(_pfile) {};
    std::string GetProtocolName() const override
    {
        return "FTP";
    }

    PayloadDataParserInterface* ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface) override;
    void HandleCommand(const std::string& line, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines);
    void HandleResponse(const std::string& line, Panels::FTP_PANEL_SUMMARY_LINES_TYPE& layerSummaryPanelLines);
};
} // namespace GView::Type::PCAP::FTP