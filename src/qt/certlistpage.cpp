#include "certlistpage.h"
#include "ui_certlistpage.h"

#include "certtablemodel.h"
#include "optionsmodel.h"
#include "bitcoingui.h"
#include "editcertdialog.h"
#include "csvmodelwriter.h"
#include "guiutil.h"

#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QMenu>

CertIssuerListPage::CertIssuerListPage(Mode mode, Tabs tab, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CertIssuerListPage),
    model(0),
    optionsModel(0),
    mode(mode),
    tab(tab)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    ui->newCertIssuer->setIcon(QIcon());
    ui->copyCertIssuer->setIcon(QIcon());
    ui->exportButton->setIcon(QIcon());
#endif

    switch(mode)
    {
    case ForTransferring:
        connect(ui->tableView, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(accept()));
        ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
        ui->tableView->setFocus();
        ui->exportButton->hide();
        break;
    case ForEditing:
        ui->buttonBox->setVisible(false);
        break;
    }
    switch(tab)
    {
    case CertIssuerTab:
        ui->labelExplanation->setText(tr("These are your registered Syscoin certs. Remember to check the expiration depth of your certs regularly."));
        break;
    case CertItemTab:
        ui->labelExplanation->setText(tr("These are your registered Syscoin certificates."));
        break;
    }

    // Context menu actions
    QAction *copyCertIssuerAction = new QAction(ui->copyCertIssuer->text(), this);
    QAction *copyCertIssuerValueAction = new QAction(tr("Copy Va&lue"), this);
    QAction *editAction = new QAction(tr("&Edit"), this);
    QAction *transferCertIssuerAction = new QAction(tr("&Transfer CertIssuer"), this);

    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyCertIssuerAction);
    contextMenu->addAction(copyCertIssuerValueAction);
    contextMenu->addAction(editAction);
    contextMenu->addSeparator();
    contextMenu->addAction(transferCertIssuerAction);

    // Connect signals for context menu actions
    connect(copyCertIssuerAction, SIGNAL(triggered()), this, SLOT(on_copyCertIssuer_clicked()));
    connect(copyCertIssuerValueAction, SIGNAL(triggered()), this, SLOT(onCopyCertIssuerValueAction()));
    connect(editAction, SIGNAL(triggered()), this, SLOT(onEditAction()));


    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));

    // Pass through accept action from button box
    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
}

CertIssuerListPage::~CertIssuerListPage()
{
    delete ui;
}

void CertIssuerListPage::setModel(CertIssuerTableModel *model)
{
    this->model = model;
    if(!model) return;

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    switch(tab)
    {
    case CertIssuerTab:
        // Receive filter
        proxyModel->setFilterRole(CertIssuerTableModel::TypeRole);
        proxyModel->setFilterFixedString(CertIssuerTableModel::CertIssuer);
        break;
    case CertItemTab:
        // Send filter
        proxyModel->setFilterRole(CertIssuerTableModel::TypeRole);
        proxyModel->setFilterFixedString(CertIssuerTableModel::CertItem);
        break;
    }
    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(0, Qt::AscendingOrder);

    // Set column widths
#if QT_VERSION < 0x050000
    ui->tableView->horizontalHeader()->setResizeMode(CertIssuerTableModel::Name, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(CertIssuerTableModel::Title, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setResizeMode(CertIssuerTableModel::ExpirationDepth, QHeaderView::ResizeToContents);
#else
    ui->tableView->horizontalHeader()->setSectionResizeMode(CertIssuerTableModel::Name, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(CertIssuerTableModel::Title, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setSectionResizeMode(CertIssuerTableModel::ExpirationDepth, QHeaderView::ResizeToContents);
#endif

    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this, SLOT(selectionChanged()));

    // Select row for newly created cert
    connect(model, SIGNAL(rowsInserted(QModelIndex,int,int)), this, SLOT(selectNewCertIssuer(QModelIndex,int,int)));

    selectionChanged();
}

void CertIssuerListPage::setOptionsModel(OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
}

void CertIssuerListPage::on_copyCertIssuer_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, CertIssuerTableModel::Name);
}

void CertIssuerListPage::onCopyCertIssuerValueAction()
{
    GUIUtil::copyEntryData(ui->tableView, CertIssuerTableModel::Title);
}

void CertIssuerListPage::onEditAction()
{
    if(!ui->tableView->selectionModel())
        return;
    QModelIndexList indexes = ui->tableView->selectionModel()->selectedRows();
    if(indexes.isEmpty())
        return;

    EditCertIssuerDialog dlg(
            tab == CertIssuerTab ?
            EditCertIssuerDialog::EditCertIssuer :
            EditCertIssuerDialog::EditCertItem);
    dlg.setModel(model);
    QModelIndex origIndex = proxyModel->mapToSource(indexes.at(0));
    dlg.loadRow(origIndex.row());
    dlg.exec();
}

void CertIssuerListPage::onTransferCertIssuerAction()
{
    QTableView *table = ui->tableView;
    QModelIndexList indexes = table->selectionModel()->selectedRows(CertIssuerTableModel::Name);

    foreach (QModelIndex index, indexes)
    {
        QString cert = index.data().toString();
        emit transferCertIssuer(cert);
    }
}

void CertIssuerListPage::on_newCertIssuer_clicked()
{
    if(!model)
        return;

    EditCertIssuerDialog dlg(
            tab == CertIssuerTab ?
            EditCertIssuerDialog::NewCertIssuer :
            EditCertIssuerDialog::NewCertItem, this);
    dlg.setModel(model);
    if(dlg.exec())
    {
        newCertIssuerToSelect = dlg.getCertIssuer();
    }
}

void CertIssuerListPage::selectionChanged()
{
    // Set button states based on selected tab and selection
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;

    if(table->selectionModel()->hasSelection())
    {
        ui->copyCertIssuer->setEnabled(true);
    }
    else
    {
        ui->copyCertIssuer->setEnabled(false);
    }
}

void CertIssuerListPage::done(int retval)
{
    QTableView *table = ui->tableView;
    if(!table->selectionModel() || !table->model())
        return;
    // When this is a tab/widget and not a model dialog, ignore "done"
    if(mode == ForEditing)
        return;

    // Figure out which cert was selected, and return it
    QModelIndexList indexes = table->selectionModel()->selectedRows(CertIssuerTableModel::Name);

    foreach (QModelIndex index, indexes)
    {
        QVariant cert = table->model()->data(index);
        returnValue = cert.toString();
    }

    if(returnValue.isEmpty())
    {
        // If no cert entry selected, return rejected
        retval = Rejected;
    }

    QDialog::done(retval);
}

void CertIssuerListPage::on_exportButton_clicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(
            this,
            tr("Export CertIssuer Data"), QString(),
            tr("Comma separated file (*.csv)"));

    if (filename.isNull()) return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(proxyModel);
    writer.addColumn("Key", CertIssuerTableModel::Name, Qt::EditRole);
    writer.addColumn("Title", CertIssuerTableModel::Title, Qt::EditRole);
    writer.addColumn("Expiration Depth", CertIssuerTableModel::ExpirationDepth, Qt::EditRole);
    if(!writer.write())
    {
        QMessageBox::critical(this, tr("Error exporting"), tr("Could not write to file %1.").arg(filename),
                              QMessageBox::Abort, QMessageBox::Abort);
    }
}



void CertIssuerListPage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}

void CertIssuerListPage::selectNewCertIssuer(const QModelIndex &parent, int begin, int /*end*/)
{
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, CertIssuerTableModel::Name, parent));
    if(idx.isValid() && (idx.data(Qt::EditRole).toString() == newCertIssuerToSelect))
    {
        // Select row of newly created cert, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newCertIssuerToSelect.clear();
    }
}
