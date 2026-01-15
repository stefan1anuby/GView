#include "FtpParser.hpp"

using namespace GView::Type::PCAP;

constexpr uint32 maxWaitUntilEndLine = 300;

// constexpr std::string_view httpPattern        = "HTTP/1.";
// constexpr std::string_view httpContentPattern = "Content-Length: ";

void GetFileExtracted(StreamTcpLayer& output)
{
}

PayloadDataParserInterface* FTP::FTPParser::ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface)
{
    return this;
}