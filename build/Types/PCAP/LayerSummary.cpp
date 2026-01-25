#include "PCAP.hpp"

using namespace GView::Type::PCAP;
using namespace GView::Type::PCAP::Panels;
using namespace AppCUI::Controls;
using namespace AppCUI::OS;

LayerSummary::LayerSummary(Reference<Object> _object, Reference<PCAPFile> _pcap)
    : TabPage("Layer Summary"), object(_object), pcap(_pcap), general(nullptr), layers(nullptr)
{
    // Create the ListView immediately, like Information does
    general = CreateChildControl<ListView>("x:0,y:0,w:100%,h:10", std::initializer_list<ConstString>{ "n:Summary,w:100" }, ListViewFlags::None);
}

void LayerSummary::SetLayers(std::vector<StreamTcpLayer>& l)
{
    layers = &l;
    Update();
}

void LayerSummary::Update()
{
    if (!general)
        return;

    general->DeleteAllItems();  // clear previous content
    UpdateLayerInformation();   // add items from layers
    RecomputePanelsPositions(); // resize
}

void LayerSummary::UpdateLayerInformation()
{
    if (!layers || !general)
        return;

    for (auto& layer : *layers) {
        if (!layer.name)
            continue;

        std::string summary = layer.extractionName.empty() ? "<no summary>" : std::string(layer.extractionName);
        general->AddItem({ summary });
    }
}

void LayerSummary::Clear()
{
    if (general)
        general->DeleteAllItems();
}

void LayerSummary::AddMessage(const std::string& msg)
{
    if (!general)
        return;

    general->AddItem({ msg });
    RecomputePanelsPositions();
}

void LayerSummary::RecomputePanelsPositions()
{
    if (!general)
        return;

    general->Resize(GetWidth(), std::min(GetHeight(), (int) general->GetItemsCount() + 3));
}
