/*
 * Co-created by Sidhujag & Saffroncoin Developer - Roshan
 * Syscoin Developers 2014
 */
#include "myaliaslistpage.h"
#include "ui_myaliaslistpage.h"
#include "aliastablemodel.h"
#include "clientmodel.h"
#include "optionsmodel.h"
#include "walletmodel.h"
#include "bitcoingui.h"
#include "editaliasdialog.h"
#include "csvmodelwriter.h"
#include "guiutil.h"

#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QMenu>
MyAliasListPage::MyAliasListPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MyAliasListPage),
    model(0),
    optionsModel(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    ui->newAlias->setIcon(QIcon());
    ui->copyAlias->setIcon(QIcon());
    ui->exportButton->setIcon(QIcon());
#endif

	ui->buttonBox->setVisible(false);

    ui->labelExplanation->setText(tr("These are your registered Syscoin Aliases. Alias operations (create, update, transfer) take 1 confirmation to appear in this table."));
	
	
    // Context menu actions
    QAction *copyAliasAction = new QAction(ui->copyAlias->text(), this);
    QAction *copyAliasValueAction = new QAction(tr("Copy Va&lue"), this);
    QAction *editAction = new QAction(tr("&Edit"), this);
    QAction *transferAliasAction = new QAction(tr("&Transfer Alias"), this);

    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyAliasAction);
    contextMenu->addAction(copyAliasValueAction);
    contextMenu->addAction(editAction);
    contextMenu->addSeparator();
    contextMenu->addAction(transferAliasAction);

    // Connect signals for context menu actions
    connect(copyAliasAction, SIGNAL(triggered()), this, SLOT(on_copyAlias_clicked()));
    connect(copyAliasValueAction, SIGNAL(triggered()), this, SLOT(onCopyAliasValueAction()));
    connect(editAction, SIGNAL(triggered()), this, SLOT(onEditAction()));
    connect(transferAliasAction, SIGNAL(triggered()), this, SLOT(onTransferAliasAction()));

    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));

    // Pass through accept action from button box
    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
}

MyAliasListPage::~MyAliasListPage()
{
    delete ui;
}
void MyAliasListPage::showEvent ( QShowEvent * event )
{
    if(!walletModel) return;
    /*if(walletModel->getEncryptionStatus() == WalletModel::Locked)
	{
        ui->labelExplanation->setText(tr("<font color='red'>WARNING: Your wallet is currently locked. For security purposes you'll need to enter your passphrase in order to interact with Syscoin Aliases. Because your wallet is locked you must manually refresh this table after creating or updating an Alias. </font> <a href=\"http://lockedwallet.syscoin.org\">more info</a><br><br>These are your registered Syscoin Aliases. Alias updates take 1 confirmation to appear in this table."));
		ui->labelExplanation->setTextFormat(Qt::RichText);
		ui->labelExplanation->setTextInteractionFlags(Qt::TextBrowserInteraction);
		ui->labelExplanation->setOpenExternalLinks(true);
    }*/
}
void MyAliasListPage::setModel(WalletModel *walletModel, AliasTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;
    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

  
		// Receive filter
		proxyModel->setFilterRole(AliasTableModel::TypeRole);
		proxyModel->setFilterFixedString(AliasTableModel::Alias);
       
    
		ui->tableView->setModel(proxyModel);
		ui->tableView->sortByColumn(0, Qt::AscendingOrder);
        ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
        ui->tableView->setSelectionMode(QAbstractItemView::SingleSelection);
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

void MyAliasListPage::setOptionsModel(ClientModel* clientmodel, OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
	this->clientModel = clientmodel;
}

void MyAliasListPage::on_copyAlias_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, AliasTableModel::Name);
}

void MyAliasListPage::onCopyAliasValueAction()
{
    GUIUtil::copyEntryData(ui->tableView, AliasTableModel::Value);
}

void MyAliasListPage::onEditAction()
{
    if(!ui->tableView->selectionModel())
        return;
    QModelIndexList indexes = ui->tableView->selectionModel()->selectedRows();
    if(indexes.isEmpty())
        return;

    EditAliasDialog dlg(EditAliasDialog::EditAlias);
    dlg.setModel(walletModel, model);
    QModelIndex origIndex = proxyModel->mapToSource(indexes.at(0));
    dlg.loadRow(origIndex.row());
    dlg.exec();
}

void MyAliasListPage::onTransferAliasAction()
{
    if(!ui->tableView->selectionModel())
        return;
    QModelIndexList indexes = ui->tableView->selectionModel()->selectedRows();
    if(indexes.isEmpty())
        return;

    EditAliasDialog dlg(EditAliasDialog::TransferAlias);
    dlg.setModel(walletModel, model);
    QModelIndex origIndex = proxyModel->mapToSource(indexes.at(0));
    dlg.loadRow(origIndex.row());
    dlg.exec();
}
void MyAliasListPage::on_refreshButton_clicked()
{
    if(!model)
        return;
    model->refreshAliasTable();
}
void MyAliasListPage::on_newAlias_clicked()
{
    if(!model)
        return;

    EditAliasDialog dlg(EditAliasDialog::NewAlias, this);
    dlg.setModel(walletModel,model);
    if(dlg.exec())
    {
        newAliasToSelect = dlg.getAlias();
    }
}
void MyAliasListPage::selectionChanged()
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

void MyAliasListPage::done(int retval)
{
    QTableView *table = ui->tableView;
    if(!table->selectionModel() || !table->model())
        return;

    // Figure out which alias was selected, and return it
    QModelIndexList indexes = table->selectionModel()->selectedRows(AliasTableModel::Name);

    foreach (QModelIndex index, indexes)
    {
        QVariant alias = table->model()->data(index);
        returnValue = alias.toString();
    }

    if(returnValue.isEmpty())
    {
        // If no alias entry selected, return rejected
        retval = Rejected;
    }

    QDialog::done(retval);
}

void MyAliasListPage::on_exportButton_clicked()
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



void MyAliasListPage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}

void MyAliasListPage::selectNewAlias(const QModelIndex &parent, int begin, int /*end*/)
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
bool MyAliasListPage::handleURI(const QString& strURI)
{
 
    return false;
}
