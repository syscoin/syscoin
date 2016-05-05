#include "escrowinfodialog.h"
#include "ui_escrowinfodialog.h"
#include "init.h"
#include "util.h"
#include "offer.h"
#include "guiutil.h"
#include "syscoingui.h"
#include "platformstyle.h"
#include <QMessageBox>
#include <QModelIndex>
#include <QDateTime>
#include <QDataWidgetMapper>
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
	GUID = idx.data(EscrowTableModel::NameRole).toString();


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
			ui->guidEdit->setText(QString::fromStdString(find_value(result.get_obj(), "escrow").get_str()));
			ui->offerEdit->setText(QString::fromStdString(find_value(result.get_obj(), "offer").get_str()));
			ui->acceptEdit->setText(QString::fromStdString(find_value(result.get_obj(), "offeracceptlink").get_str()));
			ui->txidEdit->setText(QString::fromStdString(find_value(result.get_obj(), "txid").get_str()));
			ui->titleEdit->setText(QString::fromStdString(find_value(result.get_obj(), "offertitle").get_str()));
			ui->heightEdit->setText(QString::fromStdString(find_value(result.get_obj(), "height").get_str()));
			ui->timeEdit->setText(QString::fromStdString(find_value(result.get_obj(), "time").get_str()));
			ui->priceEdit->setText(QString::fromStdString(find_value(result.get_obj(), "systotal").get_str()));
			ui->feeEdit->setText(QString::fromStdString(find_value(result.get_obj(), "sysfee").get_str()));
			ui->totalEdit->setText(QString::fromStdString(find_value(result.get_obj(), "total").get_str()));
			ui->paymessageEdit->setText(QString::fromStdString(find_value(result.get_obj(), "pay_message").get_str()));
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

