#include "offeracceptdialogbtc.h"
#include "ui_offeracceptdialogbtc.h"
#include "init.h"
#include "util.h"
#include "offerpaydialog.h"
#include "offerescrowdialog.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "platformstyle.h"
#include "syscoingui.h"
#include <QMessageBox>
#include "rpcserver.h"
#include "pubkey.h"
#include "wallet/wallet.h"
#include "walletmodel.h"
#include "main.h"
#include "utilmoneystr.h"
#include <QDesktopServices>
#if QT_VERSION < 0x050000
#include <QUrl>
#else
#include <QUrlQuery>
#endif
#include <QPixmap>
#if defined(HAVE_CONFIG_H)
#include "config/syscoin-config.h" /* for USE_QRCODE */
#endif
#ifdef USE_QRCODE
#include <qrencode.h>
#endif
using namespace std;
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
extern const CRPCTable tableRPC;
OfferAcceptDialogBTC::OfferAcceptDialogBTC(WalletModel* model, const PlatformStyle *platformStyle, QString alias, QString offer, QString quantity, QString notes, QString title, QString currencyCode, QString qstrPrice, QString sellerAlias, QString address, QWidget *parent) :
    QDialog(parent),
	walletModel(model),
    ui(new Ui::OfferAcceptDialogBTC), platformStyle(platformStyle), alias(alias), offer(offer), notes(notes), quantity(quantity), title(title), sellerAlias(sellerAlias), address(address)
{
    ui->setupUi(this);
	QString theme = GUIUtil::getThemeName();  
	ui->aboutShadeBTC->setPixmap(QPixmap(":/images/" + theme + "/about_btc"));
	dblPrice = qstrPrice.toDouble()*quantity.toUInt();
	string strfPrice = strprintf("%f", dblPrice);
	fprice = QString::fromStdString(strfPrice);
	string strCurrencyCode = currencyCode.toStdString();
	ui->bitcoinInstructionLabel->setText(tr("After paying for this item, please enter the Bitcoin Transaction ID and click on the confirm button below."));
	ui->acceptMessage->setText(tr("Are you sure you want to purchase <b>%1</b> of <b>%2</b> from merchant <b>%3</b>? Follow the steps below to successfully pay via Bitcoin:<br/><br/>1. If you are using escrow, please enter your escrow arbiter in the input box below and check the <b>Use Escrow</b> checkbox. Leave the escrow checkbox unchecked if you do not wish to use escrow.<br/>2. Open your Bitcoin wallet. You may use the QR Code to the left to scan the payment request into your wallet or click on <b>Open BTC Wallet</b> if you are on the desktop and have Bitcoin Core installed.<br/>3. Pay <b>%4 BTC</b> to <b>%5</b> using your Bitcoin wallet.<br/>4. Click on the <b>Confirm Payment</b> button once you have paid.").arg(quantity).arg(title).arg(sellerAlias).arg(fprice).arg(address));
	string strPrice = strprintf("%f", dblPrice);
	price = QString::fromStdString(strPrice);
	ui->escrowDisclaimer->setText(tr("<font color='blue'>Enter an arbiter that is mutally trusted between yourself and the merchant. Then enable the <b>Use Escrow</b> checkbox</font>"));
	ui->escrowDisclaimer->setVisible(true);
	if (!platformStyle->getImagesOnButtons())
	{
		ui->confirmButton->setIcon(QIcon());
		ui->openBtcWalletButton->setIcon(QIcon());
		ui->cancelButton->setIcon(QIcon());

	}
	else
	{
		ui->confirmButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/transaction_confirmed"));
		ui->openBtcWalletButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/send"));
		ui->cancelButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/quit"));
	}	
	this->offerPaid = false;
	connect(ui->checkBox,SIGNAL(clicked(bool)),SLOT(onEscrowCheckBoxChanged(bool)));
	connect(ui->confirmButton, SIGNAL(clicked()), this, SLOT(tryAcceptOffer()));
	connect(ui->openBtcWalletButton, SIGNAL(clicked()), this, SLOT(openBTCWallet()));

#ifdef USE_QRCODE
	QString message = tr("Payment on Syscoin Decentralized Marketplace. Offer ID %1").arg(this->offer);
	SendCoinsRecipient info;
	info.address = this->address;
	info.label = this->sellerAlias;
	info.message = message;
	ParseMoney(price.toStdString(), info.amount);
	QString uri = GUIUtil::formatBitcoinURI(info);

	ui->lblQRCode->setText("");
    if(!uri.isEmpty())
    {
        // limit URI length
        if (uri.length() > MAX_URI_LENGTH)
        {
            ui->lblQRCode->setText(tr("Resulting URI too long, try to reduce the text for label / message."));
        } else {
            QRcode *code = QRcode_encodeString(uri.toUtf8().constData(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
            if (!code)
            {
                ui->lblQRCode->setText(tr("Error encoding URI into QR Code."));
                return;
            }
            QImage myImage = QImage(code->width + 8, code->width + 8, QImage::Format_RGB32);
            myImage.fill(0xffffff);
            unsigned char *p = code->data;
            for (int y = 0; y < code->width; y++)
            {
                for (int x = 0; x < code->width; x++)
                {
                    myImage.setPixel(x + 4, y + 4, ((*p & 1) ? 0x0 : 0xffffff));
                    p++;
                }
            }
            QRcode_free(code);
            ui->lblQRCode->setPixmap(QPixmap::fromImage(myImage).scaled(128, 128));
        }
    }
#endif
	setupEscrowCheckboxState();
}
void OfferAcceptDialogBTC::on_cancelButton_clicked()
{
    reject();
}
OfferAcceptDialogBTC::~OfferAcceptDialogBTC()
{
    delete ui;
}
void OfferAcceptDialogBTC::setupEscrowCheckboxState()
{
	if(ui->checkBox->isChecked())
	{
		ui->escrowEdit->setEnabled(false);
		// get new multisig address from escrow service
		UniValue params(UniValue::VARR);
		params.push_back(this->alias.toStdString());
		params.push_back(this->offer.toStdString());
		params.push_back(ui->escrowEdit->text().trimmed().toStdString());
		UniValue resCreate;
		try
		{
			resCreate = tableRPC.execute("generateescrowmultisig", params);
		}
		catch (UniValue& objError)
		{
			ui->escrowDisclaimer->setText(tr("<font color='red'>Failed to generate multisig address: %1</font>").arg(QString::fromStdString(find_value(objError, "message").get_str())));
		}
		if (!resCreate.isObject())
		{
			ui->escrowDisclaimer->setText(tr("<font color='red'>Could not generate escrow multisig address: Invalid response from generateescrowmultisig</font>"));
			return;
		}
			
		const UniValue &o = resCreate.get_obj();
		QString multisigaddress;
		const UniValue& redeemScript_value = find_value(o, "redeemScript");
		const UniValue& address_value = find_value(o, "address");
		if (redeemScript_value.isStr())
		{
			redeemScript = QString::fromStdString(redeemScript_value.get_str());
		}
		else
		{
			ui->escrowDisclaimer->setText(tr("<font color='red'>Could not create escrow transaction: could not find redeem script in response</font>"));
			return;
		}
			
		if (address_value.isStr())
		{
			multisigaddress = QString::fromStdString(address_value.get_str());
		}
		else
		{
			ui->escrowDisclaimer->setText(tr("<font color='red'>Could not create escrow transaction: could not find redeem script in response</font>"));
			return;
		}
		ui->acceptMessage->setText(tr("Are you sure you want to purchase <b>%1</b> of <b>%2</b> from merchant <b>%3</b>? Follow the steps below to successfully pay via Bitcoin:<br/><br/>1. If you are using escrow, please enter your escrow arbiter in the input box below and check the <b>Use Escrow</b> checkbox. Leave the escrow checkbox unchecked if you do not wish to use escrow.<br/>2. Open your Bitcoin wallet. You may use the QR Code to the left to scan the payment request into your wallet or click on <b>Open BTC Wallet</b> if you are on the desktop and have Bitcoin Core installed.<br/>3. Pay <b>%4 BTC</b> to <b>%5</b> using your Bitcoin wallet.<br/>4. Click on the <b>Confirm Payment</b> button once you have paid.").arg(quantity).arg(title).arg(sellerAlias).arg(fprice).arg(multisigaddress));
		ui->escrowDisclaimer->setText(tr("<font color='green'>Escrow created successfully! Please fund using BTC address <b>%1</b></font>").arg(multisigaddress));
	}
	else
	{
		ui->escrowDisclaimer->setText(tr("<font color='blue'>Enter an arbiter that is mutally trusted between yourself and the merchant. Then enable the <b>Use Escrow</b> checkbox</font>"));
		ui->escrowEdit->setEnabled(true);
		ui->acceptMessage->setText(tr("Are you sure you want to purchase <b>%1</b> of <b>%2</b> from merchant <b>%3</b>? Follow the steps below to successfully pay via Bitcoin:<br/><br/>1. If you are using escrow, please enter your escrow arbiter in the input box below and check the <b>Use Escrow</b> checkbox. Leave the escrow checkbox unchecked if you do not wish to use escrow.<br/>2. Open your Bitcoin wallet. You may use the QR Code to the left to scan the payment request into your wallet or click on <b>Open BTC Wallet</b> if you are on the desktop and have Bitcoin Core installed.<br/>3. Pay <b>%4 BTC</b> to <b>%5</b> using your Bitcoin wallet.<br/>4. Click on the <b>Confirm Payment</b> button once you have paid.").arg(quantity).arg(title).arg(sellerAlias).arg(fprice).arg(address));
	}
}
void OfferAcceptDialogBTC::onEscrowCheckBoxChanged(bool toggled)
{
	setupEscrowCheckboxState();
}
void OfferAcceptDialogBTC::slotConfirmedFinished(QNetworkReply * reply){
	if(reply->error() != QNetworkReply::NoError) {
		ui->confirmButton->setText(m_buttonText);
		ui->confirmButton->setEnabled(true);
        QMessageBox::critical(this, windowTitle(),
            tr("Error making request: ") + reply->errorString(),
                QMessageBox::Ok, QMessageBox::Ok);
		reply->deleteLater();
		return;
	}
	double valueAmount = 0;
	QString time;
		
	QByteArray bytes = reply->readAll();
	QString str = QString::fromUtf8(bytes.data(), bytes.size());
	UniValue outerValue;
	bool read = outerValue.read(str.toStdString());
	if (read)
	{
		UniValue outerObj = outerValue.get_obj();
		UniValue statusValue = find_value(outerObj, "status");
		if (statusValue.isStr())
		{
			if(statusValue.get_str() != "success")
			{
				ui->confirmButton->setText(m_buttonText);
				ui->confirmButton->setEnabled(true);
				QMessageBox::critical(this, windowTitle(),
					tr("Transaction status not successful: ") + QString::fromStdString(statusValue.get_str()),
						QMessageBox::Ok, QMessageBox::Ok);
				reply->deleteLater();	
				return;
			}
		}
		else
		{
			ui->confirmButton->setText(m_buttonText);
			ui->confirmButton->setEnabled(true);
			QMessageBox::critical(this, windowTitle(),
				tr("Transaction status not successful: ") + QString::fromStdString(statusValue.get_str()),
					QMessageBox::Ok, QMessageBox::Ok);
			reply->deleteLater();	
			return;
		}


		UniValue dataObj1 = find_value(outerObj, "data");
		UniValue dataObj = find_value(dataObj1, "tx");
		UniValue timeValue = find_value(dataObj, "time");
		if (timeValue.isStr())
			time = QString::fromStdString(timeValue.get_str());
		UniValue hexValue = find_value(dataObj, "hex");
		if (hexValue.isStr())
			this->rawBTCTx = QString::fromStdString(hexValue.get_str());
		
		UniValue outputsValue = find_value(dataObj, "vout");
		if (outputsValue.isArray())
		{
			UniValue outputs = outputsValue.get_array();
			for (unsigned int idx = 0; idx < outputs.size(); idx++) {
				const UniValue& output = outputs[idx];	
				UniValue addressesValue = find_value(output, "addresses");
				UniValue paymentValue = find_value(output, "value");
				if(addressesValue.isArray() &&  addressesValue.get_array().size() == 1)
				{
					UniValue addressValue = addressesValue.get_array()[0];
					if(addressValue.get_str() == address.toStdString())
					{
						if(paymentValue.isNum())
						{
							valueAmount += paymentValue.get_real();
							if(valueAmount >= dblPrice)
							{
								ui->confirmButton->setText(m_buttonText);
								ui->confirmButton->setEnabled(true);
								QMessageBox::information(this, windowTitle(),
									tr("Transaction ID %1 was found in the Bitcoin blockchain! Full payment has been detected at %2.").arg(ui->btctxidEdit->text().trimmed()).arg(time),
									QMessageBox::Ok, QMessageBox::Ok);
								reply->deleteLater();
								if(ui->checkBox->isChecked())
									acceptEscrow();
								else
									acceptOffer();
								return;
							}
						}
					}
						
				}
			}
		}
	}
	else
	{
		ui->confirmButton->setText(m_buttonText);
		ui->confirmButton->setEnabled(true);
		QMessageBox::critical(this, windowTitle(),
			tr("Cannot parse JSON response: ") + str,
				QMessageBox::Ok, QMessageBox::Ok);
		reply->deleteLater();
		return;
	}
	
	reply->deleteLater();
	ui->confirmButton->setText(m_buttonText);
	ui->confirmButton->setEnabled(true);
	QMessageBox::warning(this, windowTitle(),
		tr("Payment not found in the Bitcoin blockchain! Please try again later."),
			QMessageBox::Ok, QMessageBox::Ok);	
}
void OfferAcceptDialogBTC::CheckPaymentInBTC()
{
	m_buttonText = ui->confirmButton->text();
	ui->confirmButton->setText(tr("Please Wait..."));
	ui->confirmButton->setEnabled(false);
	QNetworkAccessManager *nam = new QNetworkAccessManager(this); 
	connect(nam, SIGNAL(finished(QNetworkReply *)), this, SLOT(slotConfirmedFinished(QNetworkReply *)));
	QUrl url("http://btc.blockr.io/api/v1/tx/raw/" + ui->btctxidEdit->text().trimmed());
	QNetworkRequest request(url);
	nam->get(request);
}
// send offeraccept with offer guid/qty as params and then send offerpay with wtxid (first param of response) as param, using RPC commands.
void OfferAcceptDialogBTC::tryAcceptOffer()
{
	if (ui->btctxidEdit->text().trimmed().isEmpty()) {
        ui->btctxidEdit->setText("");
        QMessageBox::critical(this, windowTitle(),
        tr("Please enter a valid Bitcoin Transaction ID into the input box and try again"),
            QMessageBox::Ok, QMessageBox::Ok);
        return;
    }
	CheckPaymentInBTC();		
}
void OfferAcceptDialogBTC::acceptOffer(){
		if(!walletModel) return;
		WalletModel::UnlockContext ctx(walletModel->requestUnlock());
		if(!ctx.isValid())
		{
			return;
		}
		UniValue params(UniValue::VARR);
		UniValue valError;
		UniValue valResult;
		UniValue valId;
		UniValue result ;
		string strReply;
		string strError;

		string strMethod = string("offeraccept");
		if(this->quantity.toLong() <= 0)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("Invalid quantity when trying to accept offer!"),
				QMessageBox::Ok, QMessageBox::Ok);
			return;
		}
		this->offerPaid = false;
		params.push_back(this->alias.toStdString());
		params.push_back(this->offer.toStdString());
		params.push_back(this->quantity.toStdString());
		params.push_back(this->notes.toStdString());
		params.push_back(ui->btctxidEdit->text().trimmed().toStdString());

	    try {
            result = tableRPC.execute(strMethod, params);
			if (result.type() != UniValue::VNULL)
			{
				const UniValue &arr = result.get_array();
				string strResult = arr[0].get_str();
				QString offerAcceptTXID = QString::fromStdString(strResult);
				if(offerAcceptTXID != QString(""))
				{
					OfferPayDialog dlg(platformStyle, this->title, this->quantity, this->price, "BTC", this);
					dlg.exec();
					this->offerPaid = true;
					OfferAcceptDialogBTC::accept();
					return;

				}
			}
		}
		catch (UniValue& objError)
		{
			strError = find_value(objError, "message").get_str();
			QMessageBox::critical(this, windowTitle(),
			tr("Error accepting offer: \"%1\"").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
			return;
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception when accepting offer"),
				QMessageBox::Ok, QMessageBox::Ok);
			return;
		}
}
void OfferAcceptDialogBTC::acceptEscrow()
{
		if(!walletModel) return;
		WalletModel::UnlockContext ctx(walletModel->requestUnlock());
		if(!ctx.isValid())
		{
			return;
		}
		UniValue params(UniValue::VARR);
		UniValue valError;
		UniValue valResult;
		UniValue valId;
		UniValue result ;
		string strReply;
		string strError;

		string strMethod = string("escrownew");
		if(this->quantity.toLong() <= 0)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("Invalid quantity when trying to create escrow!"),
				QMessageBox::Ok, QMessageBox::Ok);
			return;
		}
		this->offerPaid = false;
		params.push_back(this->alias.toStdString());
		params.push_back(this->offer.toStdString());
		params.push_back(this->quantity.toStdString());
		params.push_back(this->notes.toStdString());
		params.push_back(ui->escrowEdit->text().toStdString());
		params.push_back(this->rawBTCTx.trimmed().toStdString());
		params.push_back(redeemScript.toStdString());


	    try {
            result = tableRPC.execute(strMethod, params);
			if (result.type() != UniValue::VNULL)
			{
				const UniValue &arr = result.get_array();
				string strResult = arr[0].get_str();
				QString escrowTXID = QString::fromStdString(strResult);
				if(escrowTXID != QString(""))
				{
					OfferEscrowDialog dlg(platformStyle, this->title, this->quantity, this->price, this);
					dlg.exec();
					this->offerPaid = true;
					OfferAcceptDialogBTC::accept();
					return;

				}
			}
		}
		catch (UniValue& objError)
		{
			strError = find_value(objError, "message").get_str();
			QMessageBox::critical(this, windowTitle(),
			tr("Error creating escrow: \"%1\"").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
			return;
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception when creating escrow"),
				QMessageBox::Ok, QMessageBox::Ok);
			return;
		}
	
   

}
void OfferAcceptDialogBTC::openBTCWallet()
{
	QString message = tr("Payment on Syscoin Decentralized Marketplace. Offer ID %1").arg(this->offer);
	SendCoinsRecipient info;
	info.address = this->address;
	info.label = this->sellerAlias;
	info.message = message;
	ParseMoney(price.toStdString(), info.amount);
	QString uri = GUIUtil::formatBitcoinURI(info);
	QDesktopServices::openUrl(QUrl(uri, QUrl::TolerantMode));
}
bool OfferAcceptDialogBTC::getPaymentStatus()
{
	return this->offerPaid;
}
