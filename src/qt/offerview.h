/*
 * Qt4/Qt5 Syscoin GUI.
 *
 * Sidhujag
 * Syscoin Developer 2014
 */
#ifndef OFFERVIEW_H
#define OFFERVIEW_H

#include <QStackedWidget>

class BitcoinGUI;
class ClientModel;
class WalletModel;
class MyOfferListPage;
class AllOfferListPage;
class AcceptandPayOfferListPage;
class AcceptedOfferListPage;
class COffer;

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
  OfferView class. This class represents the view to the syscoin offer marketplace
  
*/
class OfferView: public QObject
 {
     Q_OBJECT

public:
    explicit OfferView(QStackedWidget *parent, BitcoinGUI *_gui);
    ~OfferView();

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
    MyOfferListPage *myOfferListPage;
	AllOfferListPage *allOfferListPage;
	AcceptandPayOfferListPage *acceptandPayOfferListPage;
	AcceptedOfferListPage *acceptedOfferListPage;

public:
    /** Switch to offer page */
    void gotoOfferListPage();

signals:
    /** Signal that we want to show the main window */
    void showNormalIfMinimized();
};

#endif // OFFERVIEW_H
