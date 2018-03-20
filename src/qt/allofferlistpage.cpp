#include "allofferlistpage.h"
#include "ui_allofferlistpage.h"

#include "offertablemodel.h"
#include "optionsmodel.h"
#include "bitcoingui.h"
#include "editofferdialog.h"
#include "csvmodelwriter.h"
#include "guiutil.h"

#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QMenu>

AllOfferListPage::AllOfferListPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AllOfferListPage),
    model(0),
    optionsModel(0)
{
    ui->setupUi(this);

    //buttons get created

    
#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    ui->copyOffer->setIcon(QIcon());
    ui->exportButton->setIcon(QIcon());
#endif

    ui->labelExplanation->setText(tr("These are the first 500 registered Syscoin offers."));

    // Context menu actions
    QAction *copyOfferAction = new QAction(ui->copyOffer->text(), this);
    QAction *copyOfferValueAction = new QAction(tr("Copy Va&lue"), this);
   

    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyOfferAction);
    contextMenu->addAction(copyOfferValueAction);


    // Connect signals for context menu actions
    connect(copyOfferAction, SIGNAL(triggered()), this, SLOT(on_copyOffer_clicked()));
    connect(copyOfferValueAction, SIGNAL(triggered()), this, SLOT(onCopyOfferValueAction()));

    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));
}

AllOfferListPage::~AllOfferListPage()
{
    delete ui;
}

void AllOfferListPage::setModel(OfferTableModel *model)
{
    this->model = model;
    if(!model) return;

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
	proxyModel->setFilterRole(OfferTableModel::TypeRole);
    proxyModel->setFilterFixedString(OfferTableModel::Offer);
    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(0, Qt::AscendingOrder);

    // Set column widths
#if QT_VERSION < 0x050000
    ui->tableView->horizontalHeader()->setResizeMode(OfferTableModel::Name, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(OfferTableModel::Category, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(OfferTableModel::Title, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setResizeMode(OfferTableModel::Price, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(OfferTableModel::Quantity, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(OfferTableModel::ExpirationDepth, QHeaderView::ResizeToContents);
	ui->tableView->horizontalHeader()->setResizeMode(OfferTableModel::Description, QHeaderView::ResizeToContents);
#else
    ui->tableView->horizontalHeader()->setSectionResizeMode(OfferTableModel::Name, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(OfferTableModel::Category, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(OfferTableModel::Title, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setSectionResizeMode(OfferTableModel::Price, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(OfferTableModel::Quantity, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(OfferTableModel::ExpirationDepth, QHeaderView::ResizeToContents);
	ui->tableView->horizontalHeader()->setSectionResizeMode(OfferTableModel::Description, QHeaderView::ResizeToContents);
#endif

    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this, SLOT(selectionChanged()));

    selectionChanged();
}

void AllOfferListPage::setOptionsModel(OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
}

void AllOfferListPage::on_copyOffer_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, OfferTableModel::Name);
}

void AllOfferListPage::onCopyOfferValueAction()
{
    GUIUtil::copyEntryData(ui->tableView, OfferTableModel::Title);
}


void AllOfferListPage::selectionChanged()
{
    // Set button states based on selected tab and selection
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;

    if(table->selectionModel()->hasSelection())
    {
        ui->copyOffer->setEnabled(true);
    }
    else
    {
        ui->copyOffer->setEnabled(false);
    }
}

void AllOfferListPage::on_exportButton_clicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(
            this,
            tr("Export Offer Data"), QString(),
            tr("Comma separated file (*.csv)"));

    if (filename.isNull()) return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(proxyModel);
    writer.addColumn("Offer", OfferTableModel::Name, Qt::EditRole);
    writer.addColumn("Category", OfferTableModel::Category, Qt::EditRole);
    writer.addColumn("Title", OfferTableModel::Title, Qt::EditRole);
    writer.addColumn("Price", OfferTableModel::Price, Qt::EditRole);
    writer.addColumn("Quantity", OfferTableModel::Quantity, Qt::EditRole);
    writer.addColumn("Expiration Depth", OfferTableModel::ExpirationDepth, Qt::EditRole);
	writer.addColumn("Description", OfferTableModel::Description, Qt::EditRole);
    if(!writer.write())
    {
        QMessageBox::critical(this, tr("Error exporting"), tr("Could not write to file %1.").arg(filename),
                              QMessageBox::Abort, QMessageBox::Abort);
    }
}


void AllOfferListPage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}
bool AllOfferListPage::handleURI(const QString& strURI, COffer* offerOut)
{
 
    return false;
}