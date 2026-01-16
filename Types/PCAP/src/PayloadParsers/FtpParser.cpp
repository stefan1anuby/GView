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

        // Null-terminate
        layer.name.get()[prefixLen + payloadLen] = 0;

        applicationLayers.emplace_back(std::move(layer));
        layer.Clear();

        // Toggle for next packet
        isResponse = !isResponse;
    }

    callbackInterface->AddConnectionSummary("parsed application stream layers");
    callbackInterface->AddConnectionAppLayerName("FTP");
    return this;
}