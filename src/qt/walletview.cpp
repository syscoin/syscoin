/*
 * Qt4 bitcoin GUI.
 *
 * W.J. van der Laan 2011-2012
 * The Bitcoin Developers 2011-2013
 */
#include "walletview.h"
#include "bitcoingui.h"
#include "transactiontablemodel.h"
#include "addressbookpage.h"
#include "aliasview.h"
#include "offerview.h"
#include "certlistpage.h"
#include "sendcoinsdialog.h"
#include "signverifymessagedialog.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "optionsmodel.h"
#include "aliastablemodel.h"
#include "offertablemodel.h"
#include "transactionview.h"
#include "overviewpage.h"
#include "askpassphrasedialog.h"
#include "ui_interface.h"

#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QAction>
#if QT_VERSION < 0x050000
#include <QDesktopServices>
#else
#include <QStandardPaths>
#endif
#include <QFileDialog>
#include <QPushButton>

WalletView::WalletView(QWidget *parent, BitcoinGUI *_gui):
    QStackedWidget(parent),
    gui(_gui),
    clientModel(0),
    walletModel(0)
{
    // Create tabs
    overviewPage = new OverviewPage();
    transactionsPage = new QWidget(this);
    aliasListPage = new QStackedWidget();
    dataAliasListPage = new QStackedWidget();
    QVBoxLayout *vbox = new QVBoxLayout();
    QHBoxLayout *hbox_buttons = new QHBoxLayout();
    transactionView = new TransactionView(this);
    aliasView = new AliasView(aliasListPage, gui);
    dataAliasView = new AliasView(dataAliasListPage, gui);
	offerListPage = new QStackedWidget();
	offerView = new OfferView(offerListPage, gui);
    vbox->addWidget(transactionView);
    QPushButton *exportButton = new QPushButton(tr("&Export"), this);
    exportButton->setToolTip(tr("Export the data in the current tab to a file"));

    QPalette p;
    p.setColor(QPalette::Window, QColor(0x22, 0x22, 0x22));
    p.setColor(QPalette::Button, QColor(0x22, 0x22, 0x22));
    p.setColor(QPalette::Mid, QColor(0x22, 0x22, 0x22));
    p.setColor(QPalette::Base, QColor(0x22, 0x22, 0x22));
    p.setColor(QPalette::AlternateBase, QColor(0x22, 0x22, 0x22));
    setPalette(p);
    QFile style(":/text/res/text/style.qss");
    style.open(QFile::ReadOnly);
    setStyleSheet(QString::fromUtf8(style.readAll()));

#ifndef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    exportButton->setIcon(QIcon(":/icons/export"));
#endif
    hbox_buttons->addStretch();
    hbox_buttons->addWidget(exportButton);
    vbox->addLayout(hbox_buttons);
    transactionsPage->setLayout(vbox);

	addressBookPage = new AddressBookPage(AddressBookPage::ForEditing, AddressBookPage::SendingTab);


    certIssuerListPage = new CertIssuerListPage(CertIssuerListPage::ForEditing, CertIssuerListPage::CertIssuerTab);

    certListPage = new CertIssuerListPage(CertIssuerListPage::ForEditing, CertIssuerListPage::CertItemTab);

    receiveCoinsPage = new AddressBookPage(AddressBookPage::ForEditing, AddressBookPage::ReceivingTab);

    sendCoinsPage = new SendCoinsDialog(gui);

    signVerifyMessageDialog = new SignVerifyMessageDialog(gui);

	
    addWidget(overviewPage);
    addWidget(transactionsPage);
    addWidget(addressBookPage);
    addWidget(aliasListPage);
    addWidget(dataAliasListPage);
    addWidget(certIssuerListPage);
    addWidget(certListPage);
    addWidget(receiveCoinsPage);
    addWidget(sendCoinsPage);
	addWidget(offerListPage);

    // Clicking on a transaction on the overview page simply sends you to transaction history page
    connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), this, SLOT(gotoHistoryPage()));
    connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), transactionView, SLOT(focusTransaction(QModelIndex)));

    // Double-clicking on a transaction on the transaction history page shows details
    connect(transactionView, SIGNAL(doubleClicked(QModelIndex)), transactionView, SLOT(showDetails()));

    // Clicking on "Send Coins" in the address book sends you to the send coins tab
    connect(addressBookPage, SIGNAL(sendCoins(QString)), this, SLOT(gotoSendCoinsPage(QString)));
    // Clicking on "Verify Message" in the address book opens the verify message tab in the Sign/Verify Message dialog
    connect(addressBookPage, SIGNAL(verifyMessage(QString)), this, SLOT(gotoVerifyMessageTab(QString)));
    // Clicking on "Sign Message" in the receive coins page opens the sign message tab in the Sign/Verify Message dialog
    connect(receiveCoinsPage, SIGNAL(signMessage(QString)), this, SLOT(gotoSignMessageTab(QString)));
    // Clicking on "Export" allows to export the transaction list
    connect(exportButton, SIGNAL(clicked()), transactionView, SLOT(exportClicked()));

    gotoOverviewPage();
}

WalletView::~WalletView()
{
}

void WalletView::setBitcoinGUI(BitcoinGUI *gui)
{
    this->gui = gui;
    aliasView->setBitcoinGUI(gui);
	dataAliasView->setBitcoinGUI(gui);
	offerView->setBitcoinGUI(gui);
}

void WalletView::setClientModel(ClientModel *clientModel)
{
    this->clientModel = clientModel;
    if (clientModel)
    {
        overviewPage->setClientModel(clientModel);
        addressBookPage->setOptionsModel(clientModel->getOptionsModel());
        aliasView->setClientModel(clientModel);
		dataAliasView->setClientModel(clientModel);
        offerView->setClientModel(clientModel);
        certIssuerListPage->setOptionsModel(clientModel->getOptionsModel());
        certListPage->setOptionsModel(clientModel->getOptionsModel());
        receiveCoinsPage->setOptionsModel(clientModel->getOptionsModel());
    }
}

void WalletView::setWalletModel(WalletModel *walletModel)
{
    this->walletModel = walletModel;
    if (walletModel)
    {
        // Receive and report messages from wallet thread
        connect(walletModel, SIGNAL(message(QString,QString,unsigned int)), gui, SLOT(message(QString,QString,unsigned int)));

        // Put transaction list in tabs
        transactionView->setModel(walletModel);
        overviewPage->setWalletModel(walletModel);
        aliasView->setWalletModel(walletModel);
		dataAliasView->setWalletModel(walletModel);
        offerView->setWalletModel(walletModel);
        certIssuerListPage->setModel(walletModel->getCertIssuerTableModel());
        certListPage->setModel(walletModel->getCertIssuerTableModel());
        addressBookPage->setModel(walletModel->getAddressTableModel());
        receiveCoinsPage->setModel(walletModel->getAddressTableModel());
        sendCoinsPage->setModel(walletModel);
        signVerifyMessageDialog->setModel(walletModel);

        setEncryptionStatus();
        connect(walletModel, SIGNAL(encryptionStatusChanged(int)), gui, SLOT(setEncryptionStatus(int)));

        // Balloon pop-up for new transaction
        connect(walletModel->getTransactionTableModel(), SIGNAL(rowsInserted(QModelIndex,int,int)),
                this, SLOT(incomingTransaction(QModelIndex,int,int)));

        // Ask for passphrase if needed
        connect(walletModel, SIGNAL(requireUnlock()), this, SLOT(unlockWallet()));
    }
}

void WalletView::incomingTransaction(const QModelIndex& parent, int start, int /*end*/)
{
    // Prevent balloon-spam when initial block download is in progress
    if(!walletModel || !clientModel || clientModel->inInitialBlockDownload())
        return;

    TransactionTableModel *ttm = walletModel->getTransactionTableModel();

    QString date = ttm->index(start, TransactionTableModel::Date, parent).data().toString();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent).data(Qt::EditRole).toULongLong();
    QString type = ttm->index(start, TransactionTableModel::Type, parent).data().toString();
    QString address = ttm->index(start, TransactionTableModel::ToAddress, parent).data().toString();

    gui->incomingTransaction(date, walletModel->getOptionsModel()->getDisplayUnit(), amount, type, address);
}

void WalletView::gotoOverviewPage()
{
    gui->getOverviewAction()->setChecked(true);
    setCurrentWidget(overviewPage);
}

void WalletView::gotoHistoryPage()
{
    gui->getHistoryAction()->setChecked(true);
    setCurrentWidget(transactionsPage);
}

void WalletView::gotoAliasListPage()
{
    gui->getAliasListAction()->setChecked(true);
    setCurrentWidget(aliasListPage);
}

void WalletView::gotoDataAliasListPage()
{
    gui->getDataAliasListAction()->setChecked(true);
    setCurrentWidget(dataAliasListPage);
}

void WalletView::gotoOfferListPage()
{
	gui->getOfferListAction()->setChecked(true);
	setCurrentWidget(offerListPage);  
}
void WalletView::gotoCertIssuerListPage()
{
    gui->getCertIssuerListAction()->setChecked(true);
    setCurrentWidget(certIssuerListPage);
}

void WalletView::gotoCertListPage()
{
    gui->getCertListAction()->setChecked(true);
    setCurrentWidget(certListPage);
}

void WalletView::gotoAddressBookPage()
{
    gui->getAddressBookAction()->setChecked(true);
    setCurrentWidget(addressBookPage);
}

void WalletView::gotoReceiveCoinsPage()
{
    gui->getReceiveCoinsAction()->setChecked(true);
    setCurrentWidget(receiveCoinsPage);
}

void WalletView::gotoSendCoinsPage(QString addr)
{
    gui->getSendCoinsAction()->setChecked(true);
    setCurrentWidget(sendCoinsPage);

    if (!addr.isEmpty())
        sendCoinsPage->setAddress(addr);
}

void WalletView::gotoSignMessageTab(QString addr)
{
    // call show() in showTab_SM()
    signVerifyMessageDialog->showTab_SM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void WalletView::gotoVerifyMessageTab(QString addr)
{
    // call show() in showTab_VM()
    signVerifyMessageDialog->showTab_VM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

bool WalletView::handleURI(const QString& strURI)
{
 // URI has to be valid
    if (aliasView->handleURI(strURI))
    {
        return true;
    }
    if (dataAliasView->handleURI(strURI))
    {
        return true;
    }
    else if (offerView->handleURI(strURI))
    {
		gotoOfferListPage();
		emit showNormalIfMinimized();
        return true;
    }
    // URI has to be valid
    else if (sendCoinsPage->handleURI(strURI))
    {
        gotoSendCoinsPage();
        emit showNormalIfMinimized();
        return true;
    }
    else
        return false;
}

void WalletView::showOutOfSyncWarning(bool fShow)
{
    overviewPage->showOutOfSyncWarning(fShow);
}

void WalletView::setEncryptionStatus()
{
    gui->setEncryptionStatus(walletModel->getEncryptionStatus());
}

void WalletView::encryptWallet(bool status)
{
    if(!walletModel)
        return;
    AskPassphraseDialog dlg(status ? AskPassphraseDialog::Encrypt : AskPassphraseDialog::Decrypt, this);
    dlg.setModel(walletModel);
    dlg.exec();

    setEncryptionStatus();
}

void WalletView::backupWallet()
{
#if QT_VERSION < 0x050000
    QString saveDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
#else
    QString saveDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
#endif
    QString filename = QFileDialog::getSaveFileName(this, tr("Backup Wallet"), saveDir, tr("Wallet Data (*.dat)"));
    if (!filename.isEmpty()) {
        if (!walletModel->backupWallet(filename)) {
            gui->message(tr("Backup Failed"), tr("There was an error trying to save the wallet data to the new location."),
                      CClientUIInterface::MSG_ERROR);
        }
        else
            gui->message(tr("Backup Successful"), tr("The wallet data was successfully saved to the new location."),
                      CClientUIInterface::MSG_INFORMATION);
    }
}

void WalletView::changePassphrase()
{
    AskPassphraseDialog dlg(AskPassphraseDialog::ChangePass, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void WalletView::unlockWallet()
{
    if(!walletModel)
        return;
    // Unlock wallet when requested by wallet model
    if (walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        dlg.exec();
    }
}
