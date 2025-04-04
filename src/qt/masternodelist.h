#ifndef SYSCOIN_QT_MASTERNODELIST_H
#define SYSCOIN_QT_MASTERNODELIST_H

#include <primitives/transaction.h>
#include <sync.h>

#include <evo/deterministicmns.h>

#include <QMenu>
#include <QTimer>
#include <QWidget>

#define MASTERNODELIST_UPDATE_SECONDS 3
#define MASTERNODELIST_FILTER_COOLDOWN_SECONDS 3

namespace Ui
{
class MasternodeList;
}
class CDeterministicMN;
using CDeterministicMNCPtr = std::shared_ptr<const CDeterministicMN>;

class ClientModel;
class WalletModel;

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Masternode Manager page widget */
class MasternodeList : public QWidget
{
    Q_OBJECT

public:
    explicit MasternodeList(QWidget* parent = nullptr);
    ~MasternodeList();

    void setClientModel(ClientModel* clientModel);
    void setWalletModel(WalletModel* walletModel);

private:
    QMenu* contextMenuDIP3;
    int64_t nTimeFilterUpdatedDIP3{0};
    int64_t nTimeUpdatedDIP3{0};
    bool fFilterUpdatedDIP3{true};

    QTimer* timer;
    Ui::MasternodeList* ui{nullptr};
    ClientModel* clientModel{nullptr};
    WalletModel* walletModel{nullptr};

    // Protects tableWidgetMasternodesDIP3
    RecursiveMutex cs_dip3list;

    QString strCurrentFilterDIP3;

    bool mnListChanged{true};

    CDeterministicMNCPtr GetSelectedDIP3MN();

    void updateDIP3List();

Q_SIGNALS:
    void doubleClicked(const QModelIndex&);

private Q_SLOTS:
    void showContextMenuDIP3(const QPoint&);
    void on_filterLineEditDIP3_textChanged(const QString& strFilterIn);
    void on_checkBoxMyMasternodesOnly_stateChanged(int state);

    void extraInfoDIP3_clicked();
    void copyProTxHash_clicked();
    void copyCollateralOutpoint_clicked();
    void copyService_clicked();
    void copyPayout_clicked();
    void copyCollateral_clicked();
    void copyOwner_clicked();
    void copyVoting_clicked();
    void copyNEVMAddress_clicked();

    void handleMasternodeListChanged();
    void updateDIP3ListScheduled();
};
#endif // SYSCOIN_QT_MASTERNODELIST_H
