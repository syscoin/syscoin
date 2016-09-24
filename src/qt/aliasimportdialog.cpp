#include "aliasimportdialog.h"
#include "ui_aliasimportdialog.h"
#include "aliastablemodel.h"
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
#include <QLineEdit>
#include <QTextEdit>
#include <QGroupBox>
#include <QLabel>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include "rpc/server.h"
using namespace std;
extern CRPCTable tableRPC;
AliasImportDialog::AliasImportDialog(const PlatformStyle *platformStyle, const QModelIndex &idx, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AliasImportDialog)
{
    ui->setupUi(this);

    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
	alias = idx.data(AliasTableModel::NameRole).toString();
	QString theme = GUIUtil::getThemeName();  
	ui->aliasImportBanner->setPixmap(QPixmap(":/images/" + theme + "/" + theme + "_logo_horizontal"));
	ui->aliasImportDisclaimer->setText(tr("<font color='blue'>You may import your transactions related to alias <b>%1</b>. This is useful if the alias has been transferred to you and you wish to own services created with the alias.</font>").arg(alias));		
	if (!platformStyle->getImagesOnButtons())
	{
		ui->importButton->setIcon(QIcon());
	}
	else
	{

		ui->importButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/filesave"));
	}
}

AliasImportDialog::~AliasImportDialog()
{
    delete ui;
}

bool AliasImportDialog::on_importButton_clicked()
{
	string strMethod = string("importalias");
	UniValue params(UniValue::VARR);
	UniValue result;
	params.push_back(alias.toStdString());
    try {
        result = tableRPC.execute(strMethod, params);
		QMessageBox::information(this, windowTitle(),
			tr("Alias import successful!"),
			QMessageBox::Ok, QMessageBox::Ok);
		QDialog::accept();
		return true;	
	}
	catch (UniValue& objError)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("Could not import this alias: ") + QString::fromStdString(find_value(objError, "message").get_str()),
				QMessageBox::Ok, QMessageBox::Ok);

	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to import this alias: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
	}
	return false;
}



