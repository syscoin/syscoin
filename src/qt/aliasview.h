/*
 * Co-created by Sidhujag & Saffroncoin Developer - Roshan
 * Syscoin Developers 2014
 */
#ifndef ALIASVIEW_H
#define ALIASVIEW_H

#include <QStackedWidget>

class BitcoinGUI;
class ClientModel;
class WalletModel;
class MyAliasListPage;
class AliasListPage;


QT_BEGIN_NAMESPACE
class QObject;
class QWidget;
class QLabel;
class QModelIndex;
class QTabWidget;
class QStackedWidget;
class QAction;
QT_END_NAMESPACE

/*
  AliasView class. This class represents the view to the syscoin aliases
  
*/
class AliasView: public QObject
 {
     Q_OBJECT

public:
    explicit AliasView(QStackedWidget *parent, BitcoinGUI *_gui);
    ~AliasView();

    void setBitcoinGUI(BitcoinGUI *gui);
    /** Set the client model.
        The client model represents the part of the core that communicates with the P2P network, and is wallet-agnostic.
    */
    void setClientModel(ClientModel *clientModel);
    /** Set the wallet model.
        The wallet model represents a bitcoin wallet, and offers access to the list of transactions, address book and sending
        functionality.
    */
    void setWalletModel(WalletModel *walletModel);
    
    bool handleURI(const QString &uri);


private:
    BitcoinGUI *gui;
    ClientModel *clientModel;
    WalletModel *walletModel;

    QTabWidget *tabWidget;
    MyAliasListPage *myAliasListPage;
    AliasListPage *aliasListPage;

public:
    /** Switch to offer page */
    void gotoAliasListPage();

signals:
    /** Signal that we want to show the main window */
    void showNormalIfMinimized();
};

#endif // ALIASVIEW_H
