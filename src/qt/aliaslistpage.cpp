#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>

#include "aliaslistpage.h"
#include "ui_aliaslistpage.h"

#include "aliastablemodel.h"
#include "optionsmodel.h"
#include "walletmodel.h"
#include "bitcoingui.h"
#include "bitcoinrpc.h"
#include "editaliasdialog.h"
#include "csvmodelwriter.h"
#include "guiutil.h"
#include "ui_interface.h"
#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QKeyEvent>
#include <QMenu>
#include "main.h"
using namespace std;
using namespace json_spirit;

extern const CRPCTable tableRPC;
extern string JSONRPCReply(const Value& result, const Value& error, const Value& id);
int GetAliasDisplayExpirationDepth(int nHeight);
AliasListPage::AliasListPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AliasListPage),
    model(0),
    optionsModel(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    ui->copyAlias->setIcon(QIcon());
    ui->exportButton->setIcon(QIcon());
#endif

    ui->labelExplanation->setText(tr("Search for Syscoin Aliases"));
	
    // Context menu actions
    QAction *copyAliasAction = new QAction(ui->copyAlias->text(), this);
    QAction *copyAliasValueAction = new QAction(tr("Copy Va&lue"), this);


    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyAliasAction);
    contextMenu->addAction(copyAliasValueAction);

    // Connect signals for context menu actions
    connect(copyAliasAction, SIGNAL(triggered()), this, SLOT(on_copyAlias_clicked()));
    connect(copyAliasValueAction, SIGNAL(triggered()), this, SLOT(onCopyAliasValueAction()));
   
    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));


	ui->lineEditAliasSearch->setPlaceholderText(tr("Enter search term, regex accepted (ie: ^name returns all Aliases starting with 'name')"));
}

AliasListPage::~AliasListPage()
{
    delete ui;
}
void AliasListPage::showEvent ( QShowEvent * event )
{
    if(!walletModel) return;
    /*if(walletModel->getEncryptionStatus() == WalletModel::Locked)
	{
        ui->labelExplanation->setText(tr("<font color='red'>WARNING: Your wallet is currently locked. For security purposes you'll need to enter your passphrase in order to search Syscoin Aliases.</font> <a href=\"http://lockedwallet.syscoin.org\">more info</a>"));
		ui->labelExplanation->setTextFormat(Qt::RichText);
		ui->labelExplanation->setTextInteractionFlags(Qt::TextBrowserInteraction);
		ui->labelExplanation->setOpenExternalLinks(true);
    }*/
}
void AliasListPage::setModel(WalletModel* walletModel, AliasTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterRole(AliasTableModel::TypeRole);
    proxyModel->setFilterFixedString(AliasTableModel::Alias);
    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(0, Qt::AscendingOrder);

    // Set column widths
#if QT_VERSION < 0x050000
    ui->tableView->horizontalHeader()->setResizeMode(AliasTableModel::Name, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(AliasTableModel::Value, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setResizeMode(AliasTableModel::LastUpdateHeight, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(AliasTableModel::ExpiresOn, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(AliasTableModel::ExpiresIn, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(AliasTableModel::Expired, QHeaderView::ResizeToContents);
#else
    ui->tableView->horizontalHeader()->setSectionResizeMode(AliasTableModel::Name, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(AliasTableModel::Value, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setSectionResizeMode(AliasTableModel::LastUpdateHeight, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(AliasTableModel::ExpiresOn, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(AliasTableModel::ExpiresIn, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(AliasTableModel::Expired, QHeaderView::ResizeToContents);
#endif


    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this, SLOT(selectionChanged()));


    // Select row for newly created alias
    connect(model, SIGNAL(rowsInserted(QModelIndex,int,int)), this, SLOT(selectNewAlias(QModelIndex,int,int)));

    selectionChanged();

}

void AliasListPage::setOptionsModel(OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
}

void AliasListPage::on_copyAlias_clicked()
{
   
    GUIUtil::copyEntryData(ui->tableView, AliasTableModel::Name);
}

void AliasListPage::onCopyAliasValueAction()
{
    GUIUtil::copyEntryData(ui->tableView, AliasTableModel::Value);
}


void AliasListPage::onTransferAliasAction()
{
    QTableView *table = ui->tableView;
    QModelIndexList indexes = table->selectionModel()->selectedRows(AliasTableModel::Name);

    foreach (QModelIndex index, indexes)
    {
        QString alias = index.data().toString();
        emit transferAlias(alias);
    }
}

void AliasListPage::selectionChanged()
{
    // Set button states based on selected tab and selection
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;

    if(table->selectionModel()->hasSelection())
    {
        ui->copyAlias->setEnabled(true);
    }
    else
    {
        ui->copyAlias->setEnabled(false);
    }
}
void AliasListPage::keyPressEvent(QKeyEvent * event)
{
  if( event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter )
  {
	on_searchAlias_clicked();
    event->accept();
  }
  else
    QDialog::keyPressEvent( event );
}
void AliasListPage::on_exportButton_clicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(
            this,
            tr("Export Alias Data"), QString(),
            tr("Comma separated file (*.csv)"));

    if (filename.isNull()) return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(proxyModel);
    writer.addColumn("Alias", AliasTableModel::Name, Qt::EditRole);
    writer.addColumn("Value", AliasTableModel::Value, Qt::EditRole);
	writer.addColumn("Last Update", AliasTableModel::LastUpdateHeight, Qt::EditRole);
	writer.addColumn("Expires On", AliasTableModel::ExpiresOn, Qt::EditRole);
	writer.addColumn("Expires In", AliasTableModel::ExpiresIn, Qt::EditRole);
	writer.addColumn("Expired", AliasTableModel::Expired, Qt::EditRole);
    if(!writer.write())
    {
        QMessageBox::critical(this, tr("Error exporting"), tr("Could not write to file %1.").arg(filename),
                              QMessageBox::Abort, QMessageBox::Abort);
    }
}



void AliasListPage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}

void AliasListPage::selectNewAlias(const QModelIndex &parent, int begin, int /*end*/)
{
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, AliasTableModel::Name, parent));
    if(idx.isValid() && (idx.data(Qt::EditRole).toString() == newAliasToSelect))
    {
        // Select row of newly created alias, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newAliasToSelect.clear();
    }
}

void AliasListPage::on_searchAlias_clicked()
{
    if(!walletModel) return;
    if(ui->lineEditAliasSearch->text().trimmed().isEmpty())
    {
        QMessageBox::warning(this, tr("Error Searching Alias"),
            tr("Please enter search term"),
            QMessageBox::Ok, QMessageBox::Ok);
        return;
    }
       Array params;
        Value valError;
        Object ret ;
        Value valResult;
        Array arr;
        Value valId;
        Value result ;
        string strReply;
        string strError;
        string strMethod = string("aliasfilter");
		string name_str;
		string value_str;
		string expires_in_str;
		string lastupdate_height_str;
		string expires_on_str;
		string expired_str;
		int expired = 0;
		int expires_in = 0;
		int expires_on = 0;
		int lastupdate_height = 0;    
        params.push_back(ui->lineEditAliasSearch->text().toStdString());
        params.push_back(GetAliasDisplayExpirationDepth(pindexBest->nHeight));

        try {
            result = tableRPC.execute(strMethod, params);
        }
        catch (Object& objError)
        {
            strError = find_value(objError, "message").get_str();
            QMessageBox::critical(this, windowTitle(),
            tr("Error searching Alias: \"%1\"").arg(QString::fromStdString(strError)),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
        catch(std::exception& e)
        {
            QMessageBox::critical(this, windowTitle(),
                tr("General exception when searchig alias"),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
		if (result.type() == array_type)
			{
				this->model->clear();
			
			  Array arr = result.get_array();
			  BOOST_FOREACH(Value& input, arr)
				{
				if (input.type() != obj_type)
					continue;
				Object& o = input.get_obj();
				name_str = "";
				value_str = "";
				expires_in_str = "";
				lastupdate_height_str = "";
				expires_on_str = "";
				expired = 0;
				expires_in = 0;
				expires_on = 0;
				lastupdate_height = 0;

					const Value& name_value = find_value(o, "name");
					if (name_value.type() == str_type)
						name_str = name_value.get_str();
					const Value& value_value = find_value(o, "value");
					if (value_value.type() == str_type)
						value_str = value_value.get_str();
					const Value& lastupdate_height_value = find_value(o, "lastupdate_height");
					if (lastupdate_height_value.type() == int_type)
						lastupdate_height = lastupdate_height_value.get_int();
					const Value& expires_on_value = find_value(o, "expires_on");
					if (expires_on_value.type() == int_type)
						expires_on = expires_on_value.get_int();
					const Value& expires_in_value = find_value(o, "expires_in");
					if (expires_in_value.type() == int_type)
						expires_in = expires_in_value.get_int();
					const Value& expired_value = find_value(o, "expired");
					if (expired_value.type() == int_type)
						expired = expired_value.get_int();
				if(expired == 1)
				{
					expired_str = "Expired";
				}
				else
				{
					expired_str = "Valid";
					expires_in_str = strprintf("%d Blocks", expires_in);
					expires_on_str = strprintf("Block %d", expires_on);
				}

				
				if(lastupdate_height > 0)
					lastupdate_height_str = strprintf("Block %d", lastupdate_height);

				
				model->addRow(AliasTableModel::Alias,
						QString::fromStdString(name_str),
						QString::fromStdString(value_str),
						QString::fromStdString(lastupdate_height_str),
						QString::fromStdString(expires_on_str),
						QString::fromStdString(expires_in_str),
						QString::fromStdString(expired_str));
					this->model->updateEntry(QString::fromStdString(name_str),
						QString::fromStdString(value_str),
						QString::fromStdString(lastupdate_height_str),
						QString::fromStdString(expires_on_str),
						QString::fromStdString(expires_in_str),
						QString::fromStdString(expired_str), AllAlias, CT_NEW);	
			  }

            
         }   
        else
        {
            QMessageBox::critical(this, windowTitle(),
                tr("Error: Invalid response from aliasnew command"),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        }

}

bool AliasListPage::handleURI(const QString& strURI)
{
 
    return false;
}
