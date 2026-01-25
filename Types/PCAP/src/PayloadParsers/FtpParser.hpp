#pragma once

#include "API.hpp"

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

struct FtpSession {
    FtpUserState user;
    bool expectingPassword = false;
};
struct FTPParser : public PayloadDataParserInterface {
    std::string GetProtocolName() const override
    {
        return "FTP";
    }

    PayloadDataParserInterface* ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface) override;
    void HandleCommand(const std::string& line, ConnectionCallbackInterface* cb);
};
} // namespace GView::Type::PCAP::FTP