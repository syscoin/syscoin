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
OfferFeedbackDialog::OfferFeedbackDialog(WalletModel* model, const QString &offerStr, const QString &acceptStr, QWidget *parent) :
    QDialog(parent),
	walletModel(model),
    ui(new Ui::OfferFeedbackDialog), offer(offerStr), acceptGUID(acceptStr)
{
    ui->setupUi(this);
	QString theme = GUIUtil::getThemeName();  
	ui->aboutFeedback->setPixmap(QPixmap(":/images/" + theme + "/about_horizontal"));
	QString buyer, seller, currency, offertitle, total, systotal, reselleralias, resellerguid;
	bool reseller = false;
	if(!lookup(offerStr, acceptStr, buyer, seller, offertitle, currency, total, systotal, reseller, reselleralias, resellerguid))
	{
		ui->manageInfo2->setText(tr("Cannot find this offer purchase on the network, please try again later."));
		ui->feedbackButton->setEnabled(false);
		ui->primaryLabel->setVisible(false);
		ui->primaryRating->setVisible(false);
		ui->primaryFeedback->setVisible(false);
		return;
	}
	ui->manageInfo->setText(tr("This offer payment was for Offer ID: <b>%1</b> for <b>%2</b> totaling <b>%3 %4 (%5 SYS)</b>. The buyer is <b>%6</b>, merchant is <b>%7</b>%8").arg(offer).arg(offertitle).arg(total).arg(currency).arg(systotal).arg(buyer).arg(seller).arg(reseller? tr(" (reseller)"): ""));
	if(reseller)
	{
		seller = reselleralias;
		offer = resellerguid;
	}
	OfferType offerType = findYourOfferRoleFromAliases(buyer, seller);
	
	if(offerType == None)
	{
		ui->manageInfo2->setText(tr("You cannot leave feedback this offer purchase because you do not own either the buyer or merchant aliases. %1").arg(reseller? "The merchant as a reseller cannot leave feedback.": ""));
		ui->feedbackButton->setEnabled(false);
		ui->primaryLabel->setVisible(false);
		ui->primaryRating->setVisible(false);
		ui->primaryFeedback->setVisible(false);
	}
	if(offerType == Buyer)
	{
		ui->primaryLabel->setText("Choose a rating for the merchant (1-5) or leave at 0 for no rating. Below please give feedback to the merchant.");
		ui->manageInfo2->setText(tr("You are the <b>buyer</b> of this offer, please send feedback and rate the merchant once you have confirmed that you have recieved the item as per the description of the offer."));
	}
	else if(offerType == Seller)
	{
		ui->primaryLabel->setText("Choose a rating for the buyer (1-5) or leave at 0 for no rating. Below please give feedback to the buyer.");
		ui->manageInfo2->setText(tr("You are the <b>merchant</b> of this offer, you may leave feedback and rate the buyer once you confirmed you have recieved full payment from buyer and you have ship the goods (if its for a physical good)."));
	}
}
bool OfferFeedbackDialog::lookup(const QString &offer, const QString &acceptGuid, QString &buyer, QString &seller, QString &offertitle, QString &currency, QString &total, QString &systotal, bool &reseller, QString &reselleralias, QString &resellerguid)
{
	string strError;
	string strMethod = string("offeracceptlist");
	UniValue params(UniValue::VARR);
	params.push_back(acceptGuid.toStdString());
	UniValue offerAcceptsValue;
	reseller = false;
    try {
        offerAcceptsValue = tableRPC.execute(strMethod, params);

		if (offerAcceptsValue.type() == UniValue::VARR)
		{
			QString offerAcceptHash;
			const UniValue &offerAccepts = offerAcceptsValue.get_array();
		    for (unsigned int idx = 0; idx < offerAccepts.size(); idx++) {
			    const UniValue& accept = offerAccepts[idx];		
				const UniValue& acceptObj = accept.get_obj();
				offerAcceptHash = QString::fromStdString(find_value(acceptObj, "id").get_str());
				buyer = QString::fromStdString(find_value(acceptObj, "buyer").get_str());
				currency = QString::fromStdString(find_value(acceptObj, "currency").get_str());
				total = QString::fromStdString(find_value(acceptObj, "total").get_str());
				systotal = QString::number(ValueFromAmount(find_value(acceptObj.get_obj(), "systotal").get_int64()).get_real());
				break;
			}
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
	UniValue result(UniValue::VOBJ);
	strMethod = string("offerinfo");
	UniValue params1(UniValue::VARR);
	params1.push_back(offer.toStdString());
    try {
        result = tableRPC.execute(strMethod, params1);

		if (result.type() == UniValue::VOBJ)
		{
			seller = QString::fromStdString(find_value(result.get_obj(), "alias").get_str());
			offertitle = QString::fromStdString(find_value(result.get_obj(), "title").get_str());
			string offerlinkStr = find_value(result.get_obj(), "offerlink").get_str();
			if(offerlinkStr == "true")
			{
				reseller = true;
				reselleralias = QString::fromStdString(find_value(result.get_obj(), "offerlink_seller").get_str());
				resellerguid = QString::fromStdString(find_value(result.get_obj(), "offerlink_guid").get_str());
			}
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
			tr("Could find alias: %1").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to refresh get alias: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
	}   
	return false;
}
