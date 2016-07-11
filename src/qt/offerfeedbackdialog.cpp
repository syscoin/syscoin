#include "offerfeedbackdialog.h"
#include "ui_offerfeedbackdialog.h"

#include "guiutil.h"
#include "syscoingui.h"
#include "platformstyle.h"
#include "ui_interface.h"
#include <QMessageBox>
#include "rpcserver.h"
#include "walletmodel.h"
using namespace std;

extern const CRPCTable tableRPC;
OfferFeedbackDialog::OfferFeedbackDialog(WalletModel* model, const QString &offer, const QString &accept, QWidget *parent) :
    QDialog(parent),
	walletModel(model),
    ui(new Ui::OfferFeedbackDialog), offer(offer), acceptGUID(accept)
{
    ui->setupUi(this);
	QString theme = GUIUtil::getThemeName();  
	ui->aboutFeedback->setPixmap(QPixmap(":/images/" + theme + "/about_horizontal"));
	QString buyer, seller, currency, offertitle, total, systotal;
	if(!lookup(buyer, seller, offertitle, currency, total, systotal))
	{
		ui->manageInfo2->setText(tr("Cannot find this offer accept on the network, please try again later."));
		ui->feedbackButton->setEnabled(false);
		ui->primaryLabel->setVisible(false);
		ui->primaryRating->setVisible(false);
		ui->primaryFeedback->setVisible(false);
		return;
	}
	OfferType offerType = findYourOfferRoleFromAliases(buyer, seller);
	ui->manageInfo->setText(tr("This offer payment was for Offer ID: <b>%1</b> for <b>%2</b> totaling <b>%3 %4 (%5 SYS)</b>. The buyer is <b>%6</b>, merchant is <b>%7</b>").arg(offer).arg(offertitle).arg(total).arg(currency).arg(systotal).arg(buyer).arg(seller));
	if(offerType == None)
	{
		ui->manageInfo2->setText(tr("You cannot leave feedback this offer accept because you do not own either the buyer, or merchant aliases."));
		ui->feedbackButton->setEnabled(false);
		ui->primaryLabel->setVisible(false);
		ui->primaryRating->setVisible(false);
		ui->primaryFeedback->setVisible(false);
	}
	if(offerType == Buyer)
	{
		ui->manageInfo2->setText(tr("You are the <b>buyer</b> of this offer, you may release the feedback for the merchant once you have confirmed that you have recieved the item as per the description of the offer."));
	}
	else if(offerType == Seller)
	{
		ui->manageInfo2->setText(tr("You are the <b>merchant</b> of the offer held in escrow, you may leave feedback for the buyer once you confirmed you have recieved full payment from buyer and you have ship the goods (if its for a physical good)."));
	}
}
bool OfferFeedbackDialog::lookup(QString &buyer, QString &seller, QString &offertitle, QString &currency, QString &total, QString &systotal)
{
	string strError;
	string strMethod = string("offerinfo");
	UniValue params(UniValue::VARR);
	UniValue result;
	params.push_back(offer.toStdString());

    try {
        result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VOBJ)
		{
			UniValue offerAcceptsValue = find_value(result.get_obj(), "accepts");
			if(offerAcceptsValue.type() != UniValue::VARR)
				return false;
			seller = QString::fromStdString(find_value(result.get_obj(), "alias").get_str());
			QString offerAcceptHash;
			const UniValue &offerAccepts = offerAcceptsValue.get_array();
		    for (unsigned int idx = 0; idx < offerAccepts.size(); idx++) {
			    const UniValue& accept = offerAccepts[idx];				
				const UniValue& acceptObj = accept.get_obj();
				offerAcceptHash = QString::fromStdString(find_value(acceptObj, "id").get_str());
				if(offerAcceptHash != acceptGUID)
					continue;

				currency = QString::fromStdString(find_value(acceptObj, "currency").get_str());
				total = QString::fromStdString(find_value(acceptObj, "total").get_str());
				systotal = QString::fromStdString(find_value(acceptObj, "systotal").get_str());
				break;
			}
			if(offerAcceptHash != acceptGUID)
			{
				return false;
			}
			offertitle = QString::fromStdString(find_value(result.get_obj(), "title").get_str());
			return true;
		}
		 

	}
	catch (UniValue& objError)
	{
		return false;
	}
	catch(std::exception& e)
	{
		return false;
	}
	return false;
}
void OfferFeedbackDialog::on_cancelButton_clicked()
{
    reject();
}
OfferFeedbackDialog::~OfferFeedbackDialog()
{
    delete ui;
}
void OfferFeedbackDialog::on_feedbackButton_clicked()
{
	UniValue params(UniValue::VARR);
	string strMethod = string("offeracceptfeedback");
	params.push_back(offer.toStdString());
	params.push_back(acceptGUID.toStdString());
	params.push_back(ui->primaryFeedback->toPlainText().toStdString());
	params.push_back(ui->primaryRating->cleanText().toStdString());
	try {
		UniValue result = tableRPC.execute(strMethod, params);
		QMessageBox::information(this, windowTitle(),
		tr("Thank you for your feedback!"),
			QMessageBox::Ok, QMessageBox::Ok);
		OfferFeedbackDialog::accept();
	}
	catch (UniValue& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
        tr("Error sending feedback: \"%1\"").arg(QString::fromStdString(strError)),
			QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
            tr("General exception sending offeracceptfeedback"),
			QMessageBox::Ok, QMessageBox::Ok);
	}	
}

OfferFeedbackDialog::OfferType OfferFeedbackDialog::findYourOfferRoleFromAliases(const QString &buyer, const QString &seller)
{
	if(isYourAlias(buyer))
		return Buyer;
	else if(isYourAlias(seller))
		return Seller;
	else
		return None;
    
 
}
bool OfferFeedbackDialog::isYourAlias(const QString &alias)
{
	string strMethod = string("aliasinfo");
    UniValue params(UniValue::VARR); 
	UniValue result ;
	params.push_back(alias.toStdString());	
	try {
		result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VOBJ)
		{
			const UniValue& o = result.get_obj();
			const UniValue& mine_value = find_value(o, "ismine");
			if (mine_value.type() == UniValue::VBOOL)
				return mine_value.get_bool();		

		}
	}
	catch (UniValue& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
			tr("Could find your alias: %1").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to refresh the cert list: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
	}   
	return false;
}
