#include "escrowinfodialog.h"
#include "ui_escrowinfodialog.h"
#include "init.h"
#include "util.h"
#include "escrow.h"
#include "guiutil.h"
#include "syscoingui.h"
#include "escrowtablemodel.h"
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

EscrowInfoDialog::EscrowInfoDialog(const PlatformStyle *platformStyle, const QModelIndex &idx, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EscrowInfoDialog)
{
    ui->setupUi(this);

    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
	GUID = idx.data(EscrowTableModel::EscrowRole).toString();


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

EscrowInfoDialog::~EscrowInfoDialog()
{
    delete ui;
}
void EscrowInfoDialog::on_okButton_clicked()
{
    mapper->submit();
    accept();
}
bool EscrowInfoDialog::lookup()
{
	string strError;
	string strMethod = string("escrowinfo");
	UniValue params(UniValue::VARR);
	UniValue result;
	params.push_back(GUID.toStdString());

    try {
        result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VOBJ)
		{
			string seller = find_value(result.get_obj(), "seller").get_str();
			string arbiter = find_value(result.get_obj(), "arbiter").get_str();
			string buyer = find_value(result.get_obj(), "buyer").get_str();
			ui->guidEdit->setText(QString::fromStdString(find_value(result.get_obj(), "escrow").get_str()));
			ui->offerEdit->setText(QString::fromStdString(find_value(result.get_obj(), "offer").get_str()));
			ui->acceptEdit->setText(QString::fromStdString(find_value(result.get_obj(), "offeracceptlink").get_str()));
			ui->txidEdit->setText(QString::fromStdString(find_value(result.get_obj(), "txid").get_str()));
			ui->titleEdit->setText(QString::fromStdString(find_value(result.get_obj(), "offertitle").get_str()));
			ui->heightEdit->setText(QString::fromStdString(find_value(result.get_obj(), "height").get_str()));
			ui->timeEdit->setText(QString::fromStdString(find_value(result.get_obj(), "time").get_str()));
			ui->priceEdit->setText(QString::number(AmountFromValue(find_value(result.get_obj(), "systotal"))));
			ui->feeEdit->setText(QString::number(AmountFromValue(find_value(result.get_obj(), "sysfee"))));

			ui->totalEdit->setText(QString::fromStdString(find_value(result.get_obj(), "total").get_str()));
			ui->paymessageEdit->setText(QString::fromStdString(find_value(result.get_obj(), "pay_message").get_str()));
			int avgRating = find_value(result.get_obj(), "avg_rating").get_int();
			ui->ratingEdit->setText(tr("%1 Stars").arg(QString::number(avgRating));
			UniValue buyerFeedback = find_value(result.get_obj(), "buyer_feedback").get_array());
			UniValue sellerFeedback = find_value(result.get_obj(), "seller_feedback").get_array());
			UniValue arbiterFeedback = find_value(result.get_obj(), "arbiter_feedback").get_array());
			for(unsigned int i = 0;i<buyerFeedback.size(); i++)
			{
				UniValue feedbackObj = buyerFeedback[i].get_obj();
				int rating =  find_value(feedbackObj, "rating").get_int());
				int user =  find_value(feedbackObj, "feedbackuser").get_int());
				string feedback =  find_value(feedbackObj, "feedback").get_str());
				QGroupBox *groupBox = new QGroupBox(tr("Buyer Feedback #%1").arg(QString::number(i)));
				QTextEdit *feedbackText = new QTextEdit(QString::fromStdString(feedback));
				feedbackText->setEnabled(false);
				QVBoxLayout *vbox = new QVBoxLayout;
				QHBoxLayout *userBox = new QHBoxLayout;
				QLabel *userLabel = new QLabel(tr("From:")));

				QString userStr = "";
				if(user == BUYER)
				{
					userStr = tr("%1 (Buyer)").arg(QString::fromStdString(buyer));
				}
				else if(user == SELLER)
				{
					userStr = tr("%1 (Merchant)").arg(QString::fromStdString(seller));
				}
				else if(user == Arbiter)
				{
					userStr = tr("%1 (Arbiter)").arg(QString::fromStdString(arbiter));
				}
				QLineEdit *userText = new QLineEdit(QString::fromStdString(userStr));
				userText->setEnabled(false);
				userBox->addWidget(userLabel);
				userBox->addWidget(userText);
				userBox->addStretch(1);
				vbox->addLayout(userBox);
			 `` QHBoxLayout *ratingBox = new QHBoxLayout;
				QLabel *ratingLabel = new QLabel(tr("Rating:"));
				QLineEdit *ratingText = new QLineEdit(tr("%1 Stars").arg(QString::number(rating)));
				ratingText->setEnabled(false);
				ratingBox->addWidget(ratingLabel);
				ratingBox->addWidget(ratingText);
				ratingBox->addStretch(1);
				vbox->addLayout(ratingBox);
				vbox->addWidget(feedbackText);
				groupBox->setLayout(vbox);
				ui->buyerFeedbackLayout->addWidget(groupBox);
			}
			return true;
		}
		 

	}
	catch (UniValue& objError)
	{
		QMessageBox::critical(this, windowTitle(),
				tr("Could not find this escrow, please check the escrow ID and that it has been confirmed by the blockchain"),
				QMessageBox::Ok, QMessageBox::Ok);

	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to locate this escrow, please check the escrow ID and that it has been confirmed by the blockchain: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
	}
	return false;


}

