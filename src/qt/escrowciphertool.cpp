#include "escrowciphertool.h"
#include "ui_escrowciphertool.h"
#include "init.h"
#include "util.h"
#include "offer.h"
#include "guiutil.h"
#include "syscoingui.h"
#include "escrowtablemodel.h"
#include "platformstyle.h"
#include <QMessageBox>
#include <QModelIndex>
#include <QDateTime>
#include <QDataWidgetMapper>
#include "rpcserver.h"
using namespace std;

extern const CRPCTable tableRPC;

EscrowCipherTool::EscrowCipherTool(const PlatformStyle *platformStyle, const QModelIndex &idx, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EscrowCipherTool)
{
    ui->setupUi(this);

    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
	GUID = idx.data(EscrowTableModel::EscrowRole).toString();


	QString theme = GUIUtil::getThemeName();  
	if (!platformStyle->getImagesOnButtons())
	{
		ui->okButton->setIcon(QIcon());
		ui->calculateButton->setIcon(QIcon());

	}
	else
	{
		ui->okButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/synced"));
		ui->calculateButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/verify"));
	}
	ui->cipherInfo->setText(tr("This is a tool designed to verify that the payment message that the seller provides to an arbiter is correct. Please enter the payment message sent to the seller by the buyer in the Message section. The calculated cipher should match the Payment Message Cipher. If it doesn't then the payment message is incorrect."));
	lookup();
}

EscrowCipherTool::~EscrowCipherTool()
{
    delete ui;
}
void EscrowCipherTool::on_okButton_clicked()
{
    mapper->submit();
    accept();
}
void EscrowCipherTool::on_calculuateButton_clicked()
{
	string strError;
	string strMethod = string("escrowcipher");
	UniValue params(UniValue::VARR);
	UniValue result;
	params.push_back(ui->labelAlias->text().toStdString());
	params.push_back(ui->messageEdit->toPlainText().toStdString());

    try {
        result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VARR)
		{
			const UniValue &arr = result.get_array();
			string strResult = arr[0].get_str();
			ui->labelCipher->setText(QString::fromStdString(strResult));
			if(ui->labelCipher->text() == ui->labelEscrowCipher->text())
			{
				ui->labelResult->setText("<font color='green'>Payment message is <b>correct</b>. Calculated and Payment Message Cipher's match!</font>");
			}
			{
				ui->labelResult->setText("<font color='red'>Payment message is <b>incorrect</b>. Calculated and Payment Message Cipher's do not match!</font>");
			}
		}	 
	}
	catch (UniValue& objError)
	{
		QMessageBox::critical(this, windowTitle(),
				tr("Could not update cipher, please try again!"),
				QMessageBox::Ok, QMessageBox::Ok);

	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to update cipher, please try again!"),
				QMessageBox::Ok, QMessageBox::Ok);
	}
}
bool EscrowCipherTool::lookup()
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
			ui->labelAlias->setText(QString::fromStdString(find_value(result.get_obj(), "seller").get_str()));
			ui->labelEscrowCipher->setText(QString::fromStdString(find_value(result.get_obj(), "rawpay_message").get_str()));
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

