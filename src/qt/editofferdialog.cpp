#include "editofferdialog.h"
#include "ui_editofferdialog.h"

#include "offertablemodel.h"

#include "guiutil.h"
#include "bitcoingui.h"
#include "ui_interface.h"
#include "bitcoinrpc.h"
#include <QDataWidgetMapper>
#include <QMessageBox>
#include <QString>
using namespace std;
using namespace json_spirit;
extern const CRPCTable tableRPC;
EditOfferDialog::EditOfferDialog(Mode mode, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EditOfferDialog), mapper(0), mode(mode), model(0)
{
    ui->setupUi(this);

    GUIUtil::setupAddressWidget(ui->nameEdit, this);

    switch(mode)
    {
    case NewOffer:
        setWindowTitle(tr("New offer"));
        break;
    case EditOffer:
        setWindowTitle(tr("Edit offer"));
        break;
    }

    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
}

EditOfferDialog::~EditOfferDialog()
{
    delete ui;
}

void EditOfferDialog::setModel(OfferTableModel *model)
{
    this->model = model;
    if(!model) return;

    mapper->setModel(model);
    mapper->addMapping(ui->nameEdit, OfferTableModel::Name);
    mapper->addMapping(ui->catEdit, OfferTableModel::Category);
	mapper->addMapping(ui->titleEdit, OfferTableModel::Title);
	mapper->addMapping(ui->priceEdit, OfferTableModel::Price);
	mapper->addMapping(ui->qtyEdit, OfferTableModel::Quantity);
	mapper->addMapping(ui->descriptionEdit, OfferTableModel::Description);
}

void EditOfferDialog::loadRow(int row)
{
    mapper->setCurrentIndex(row);
}

bool EditOfferDialog::saveCurrentRow()
{
    if(!model) return false;
	Array params;
	string strMethod;
    switch(mode)
    {
    case NewOffer:

		/*"<address> offerpay receive address, wallet default address if not specified.\n"
						"<category> category, 255 chars max.\n"
						"<title> title, 255 chars max.\n"
						"<quantity> quantity, > 0\n"
						"<price> price in syscoin, > 0\n"
						"<description> description, 64 KB max.\n"
						*/
		strMethod = string("offernew");
		params.push_back(ui->catEdit->text().toStdString());
		params.push_back(ui->titleEdit->text().toStdString());
		params.push_back(ui->qtyEdit->text().toStdString());
		params.push_back(ui->priceEdit->text().toStdString());		
		params.push_back(ui->descriptionEdit->toPlainText().toStdString());
		try {
            Value result = tableRPC.execute(strMethod, params);
			if (result.type() == array_type)
			{
				Array arr = result.get_array();
				strMethod = string("offeractivate");
				params.clear();
				params.push_back(arr[1].get_str());
				result = tableRPC.execute(strMethod, params);
				if (result.type() != null_type)
				{
					offer = model->addRow(OfferTableModel::Offer,
								ui->nameEdit->text(),
								ui->catEdit->text(),
								ui->titleEdit->text(),
								ui->priceEdit->text(),
								ui->qtyEdit->text(),
								ui->descriptionEdit->toPlainText(),
								"N/A");


					this->model->updateEntry(QString::fromStdString(arr[1].get_str()), ui->titleEdit->text(), ui->catEdit->text(), ui->priceEdit->text(), ui->qtyEdit->text(), ui->descriptionEdit->toPlainText(),QString::fromStdString("N/A"), MyOffers, CT_NEW);					
					QMessageBox::information(this, windowTitle(),
					tr("New offer created successfully! GUID for the new offer is: \"%1\"").arg(QString::fromStdString(arr[1].get_str())),
					QMessageBox::Ok, QMessageBox::Ok);
				}	
			}
		}
		catch (Object& objError)
		{
			string strError = find_value(objError, "message").get_str();
			QMessageBox::critical(this, windowTitle(),
			tr("Error creating new offer: \"%1\"").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception creating new offer"),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}							

        break;
    case EditOffer:
        if(mapper->submit())
        {
			strMethod = string("offerupdate");
			params.push_back(ui->nameEdit->text().toStdString());
			params.push_back(ui->catEdit->text().toStdString());
			params.push_back(ui->titleEdit->text().toStdString());
			params.push_back(ui->qtyEdit->text().toStdString());
			params.push_back(ui->priceEdit->text().toStdString());		
			params.push_back(ui->descriptionEdit->toPlainText().toStdString());
			try {
				Value result = tableRPC.execute(strMethod, params);
				if (result.type() != null_type)
				{
					string strResult = result.get_str();
					offer = ui->nameEdit->text() + ui->catEdit->text() + ui->titleEdit->text()+ ui->priceEdit->text()+ ui->qtyEdit->text() + ui->descriptionEdit->toPlainText();


					this->model->updateEntry(ui->nameEdit->text(), ui->titleEdit->text(), ui->catEdit->text(), ui->priceEdit->text(), ui->qtyEdit->text(), ui->descriptionEdit->toPlainText(), QString::fromStdString("N/A"), MyOffers ,CT_UPDATED);
					QMessageBox::information(this, windowTitle(),
					tr("Offer updated successfully! Transaction Id for the update is: \"%1\"").arg(QString::fromStdString(strResult)),
						QMessageBox::Ok, QMessageBox::Ok);
						
				}
			}
			catch (Object& objError)
			{
				string strError = find_value(objError, "message").get_str();
				QMessageBox::critical(this, windowTitle(),
				tr("Error updating offer: \"%1\"").arg(QString::fromStdString(strError)),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
					tr("General exception updating offer"),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}	
            
        }
        break;
    }
    return !offer.isEmpty();
}

void EditOfferDialog::accept()
{
    if(!model) return;

    if(!saveCurrentRow())
    {
        switch(model->getEditStatus())
        {
        case OfferTableModel::OK:
            // Failed with unknown reason. Just reject.
            break;
        case OfferTableModel::NO_CHANGES:
            // No changes were made during edit operation. Just reject.
            break;
        case OfferTableModel::INVALID_OFFER:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered offer \"%1\" is not a valid Syscoin offer.").arg(ui->nameEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case OfferTableModel::DUPLICATE_OFFER:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered offer \"%1\" is already taken.").arg(ui->nameEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case OfferTableModel::WALLET_UNLOCK_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("Could not unlock wallet."),
                QMessageBox::Ok, QMessageBox::Ok);
            break;

        }
        return;
    }
    QDialog::accept();
}
QString EditOfferDialog::getOffer() const
{
    return offer;
}


