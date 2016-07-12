#include "offeracceptinfodialog.h"
#include "ui_offeracceptinfodialog.h"
#include "init.h"
#include "util.h"
#include "offer.h"
#include "guiutil.h"
#include "syscoingui.h"
#include "offeraccepttablemodel.h"
#include "platformstyle.h"
#include <QMessageBox>
#include <QModelIndex>
#include <QDateTime>
#include <QDataWidgetMapper>
#include <QLineEdit>
#include <QTextEdit>
#include <QGroupBox>
#include <QLabel>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include "rpcserver.h"
using namespace std;

extern const CRPCTable tableRPC;

OfferAcceptInfoDialog::OfferAcceptInfoDialog(const PlatformStyle *platformStyle, const QModelIndex &idx, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::OfferAcceptInfoDialog)
{
    ui->setupUi(this);

    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
	offerGUID = idx.data(OfferAcceptTableModel::NameRole).toString();
	offerAcceptGUID = idx.data(OfferAcceptTableModel::GUIDRole).toString();
	ui->linkGUIDEdit->setVisible(false);
	ui->linkGUIDLabel->setVisible(false);
	ui->commissionEdit->setVisible(false);
	ui->commissionLabel->setVisible(false);
	ui->btctxidEdit->setVisible(false);
	ui->btctxidLabel->setVisible(false);
	ui->certEdit->setVisible(false);
	ui->certLabel->setVisible(false);
	ui->escrowEdit->setVisible(false);
	ui->escrowLabel->setVisible(false);
	QString theme = GUIUtil::getThemeName();  
	if (!platformStyle->getImagesOnButtons())
	{
		ui->okButton->setIcon(QIcon());

	}
	else
	{
		ui->okButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/synced"));
	}
	lookup();
}

OfferAcceptInfoDialog::~OfferAcceptInfoDialog()
{
    delete ui;
}
void OfferAcceptInfoDialog::on_okButton_clicked()
{
    mapper->submit();
    accept();
}
void OfferAcceptInfoDialog::SetFeedbackUI(const UniValue &feedbackObj, const QString &userType, const QString& buyer, const QString& seller)
{
	if(feedbackObj.size() <= 0)
	{
		QLabel *noFeedback = new QLabel(tr("No Feedback Found"));
		noFeedback->setAlignment(Qt::AlignLeft | Qt::AlignTop);
		if(userType == tr("Buyer"))
			ui->buyerFeedbackLayout->addWidget(noFeedback);
		else if(userType == tr("Seller"))
			ui->sellerFeedbackLayout->addWidget(noFeedback);
		return;
	}
	for(unsigned int i = 0;i<feedbackObj.size(); i++)
	{
		UniValue feedbackValue = feedbackObj[i].get_obj();
		int rating =  find_value(feedbackValue, "rating").get_int();
		int user =  find_value(feedbackValue, "feedbackuser").get_int();
		string feedback =  find_value(feedbackValue, "feedback").get_str();
		QString time =  QString::fromStdString(find_value(feedbackValue, "time").get_str());
		QGroupBox *groupBox = new QGroupBox(tr("%1 Feedback #%2").arg(userType).arg(QString::number(i+1)));
		QTextEdit *feedbackText;
		if(feedback.size() > 0)
			feedbackText = new QTextEdit(QString::fromStdString(feedback));
		else
			feedbackText = new QTextEdit(tr("No Feedback"));

		QVBoxLayout *vbox = new QVBoxLayout;
		QHBoxLayout *timeBox = new QHBoxLayout;
		QLabel *timeLabel = new QLabel(tr("Time:"));
		QDateTime dateTime;	
		int unixTime = time.toInt();
		dateTime.setTime_t(unixTime);
		time = dateTime.toString();	
		QLabel *timeText = new QLabel(tr("<b>%1</b>").arg(time));
		timeBox->addWidget(timeLabel);
		timeBox->addWidget(timeText);
		timeBox->addStretch(1);
		vbox->addLayout(timeBox);

		QHBoxLayout *userBox = new QHBoxLayout;
		QLabel *userLabel = new QLabel(tr("From:"));

		QString userStr = "";
		if(user == ACCEPTBUYER)
		{
			userStr = tr("%1 (Merchant)").arg(seller);
		}
		else if(user == ACCEPTSELLER)
		{
			userStr = tr("%1 (Buyer)").arg(buyer);
		}
		QLabel *userText = new QLabel(tr("<b>%1</b>").arg(userStr));
		userBox->addWidget(userLabel);
		userBox->addWidget(userText);
		userBox->addStretch(1);
		vbox->addLayout(userBox);
	
		QHBoxLayout *ratingBox = new QHBoxLayout;
		QLabel *ratingLabel = new QLabel(tr("Rating:"));
		QLabel *ratingText;
		if(rating > 0)
			ratingText = new QLabel( tr("<b>%1 Stars</b>").arg(QString::number(rating)));
		else
			ratingText = new QLabel( tr("<b>No Rating</b>"));

		ratingBox->addWidget(ratingLabel);
		ratingBox->addWidget(ratingText);
		ratingBox->addStretch(1);
		vbox->addLayout(ratingBox);
		
		
		vbox->addWidget(feedbackText);

		groupBox->setLayout(vbox);
		if(userType == tr("Buyer"))
			ui->buyerFeedbackLayout->addWidget(groupBox);
		else if(userType == tr("Seller"))
			ui->sellerFeedbackLayout->addWidget(groupBox);
	}
}
bool OfferAcceptInfoDialog::lookup()
{
	string strError;
	string strMethod = string("offerinfo");
	UniValue params(UniValue::VARR);
	UniValue result;
	params.push_back(offerGUID.toStdString());

    try {
        result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VOBJ)
		{
			UniValue offerAcceptsValue = find_value(result.get_obj(), "accepts");
			if(offerAcceptsValue.type() != UniValue::VARR)
				return false;
			QString sellerStr = QString::fromStdString(find_value(result.get_obj(), "alias").get_str());
			ui->sellerEdit->setText(sellerStr);
			QString linkedStr = QString::fromStdString(find_value(result.get_obj(), "offerlink").get_str());
			if(linkedStr == QString("true"))
			{

				ui->linkGUIDEdit->setVisible(true);
				ui->linkGUIDLabel->setVisible(true);
				ui->commissionEdit->setVisible(true);
				ui->commissionLabel->setVisible(true);
				ui->linkGUIDEdit->setText(QString::fromStdString(find_value(result.get_obj(), "offerlink_guid").get_str()));
				ui->commissionEdit->setText(QString::fromStdString(find_value(result.get_obj(), "commission").get_str()));
			}
			const UniValue &offerAccepts = offerAcceptsValue.get_array();
			COfferAccept myAccept;
			QDateTime timestamp;
		    for (unsigned int idx = 0; idx < offerAccepts.size(); idx++) {
			    const UniValue& accept = offerAccepts[idx];				
				const UniValue& acceptObj = accept.get_obj();
				QString offerAcceptHash = QString::fromStdString(find_value(acceptObj, "id").get_str());
				if(offerAcceptHash != offerAcceptGUID)
					continue;
				ui->guidEdit->setText(offerAcceptHash);
				ui->txidEdit->setText(QString::fromStdString(find_value(acceptObj, "txid").get_str()));
				
				ui->heightEdit->setText(QString::fromStdString(find_value(acceptObj, "height").get_str()));
				int unixTime = atoi(find_value(acceptObj, "time").get_str().c_str());
				timestamp.setTime_t(unixTime);
				ui->timeEdit->setText(timestamp.toString());

				ui->quantityEdit->setText(QString::fromStdString(find_value(acceptObj, "quantity").get_str()));
				QString currencyStr = QString::fromStdString(find_value(acceptObj, "currency").get_str());
				if(currencyStr == "BTC")
				{
					QString btctxidStr = QString::fromStdString(find_value(acceptObj, "btctxid").get_str());
					if(btctxidStr != "")
					{
						ui->btctxidEdit->setVisible(true);
						ui->btctxidLabel->setVisible(true);
						ui->btctxidEdit->setText(btctxidStr);
					}
				}
				ui->currencyEdit->setText(currencyStr);
				
				ui->totalEdit->setText(tr("%1 SYS").arg(QString::fromStdString(find_value(acceptObj, "total").get_str())));
				ui->discountEdit->setText(QString::fromStdString(find_value(acceptObj, "offer_discount_percentage").get_str()));
				ui->paidEdit->setText(QString::fromStdString(find_value(acceptObj, "paid").get_str()));
				QString buyerStr = QString::fromStdString(find_value(acceptObj.get_obj(), "buyer").get_str());
				ui->buyerEdit->setText(buyerStr);
				ui->paymessageEdit->setText(QString::fromStdString(find_value(acceptObj, "pay_message").get_str()));
				QString escrowStr = QString::fromStdString(find_value(acceptObj.get_obj(), "escrowlink").get_str());
				if(escrowStr != "")
				{
					ui->escrowEdit->setVisible(true);
					ui->escrowLabel->setVisible(true);
					ui->escrowEdit->setText(escrowStr);
				}
				int avgRating = find_value(acceptObj.get_obj(), "avg_rating").get_int();
				ui->ratingEdit->setText(tr("%1 Stars").arg(QString::number(avgRating)));
				const UniValue &buyerFeedback = find_value(acceptObj.get_obj(), "buyer_feedback").get_array();
				const UniValue &sellerFeedback = find_value(acceptObj.get_obj(), "seller_feedback").get_array();
				SetFeedbackUI(buyerFeedback, tr("Buyer"), buyerStr, sellerStr);
				SetFeedbackUI(sellerFeedback, tr("Seller"), buyerStr, sellerStr);
			}

			ui->titleEdit->setText(QString::fromStdString(find_value(result.get_obj(), "title").get_str()));
			ui->priceEdit->setText(tr("%1 SYS").arg(QString::fromStdString(find_value(result.get_obj(), "price").get_str())));
			QString certStr = QString::fromStdString(find_value(result.get_obj(), "cert").get_str());
			if(certStr != "")
			{
				ui->certEdit->setVisible(true);
				ui->certLabel->setVisible(true);
				ui->certEdit->setText(certStr);
			}	
			return true;
		}
		 

	}
	catch (UniValue& objError)
	{
		QMessageBox::critical(this, windowTitle(),
				tr("Could not find this offer or offer accept, please check the offer ID and that it has been confirmed by the blockchain"),
				QMessageBox::Ok, QMessageBox::Ok);

	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to locate this offer or offeraccept, please check the offer ID and that it has been confirmed by the blockchain: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
	}
	return false;


}

