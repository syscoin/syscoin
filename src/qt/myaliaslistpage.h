#ifndef MyAliasListPage_H
#define MyAliasListPage_H

#include <QDialog>

namespace Ui {
    class MyAliasListPage;
}
class AliasTableModel;
class OptionsModel;
class ClientModel;
class WalletModel;
QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
QT_END_NAMESPACE

/** Widget that shows a list of owned aliases.
  */
class MyAliasListPage : public QDialog
{
    Q_OBJECT

public:


    explicit MyAliasListPage(QWidget *parent = 0);
    ~MyAliasListPage();

    void setModel(WalletModel*, AliasTableModel *model);
    void setOptionsModel(ClientModel* clientmodel, OptionsModel *optionsModel);
    const QString &getReturnValue() const { return returnValue; }
	bool handleURI(const QString &uri);
	void showEvent ( QShowEvent * event );
public slots:
    void done(int retval);

private:
	ClientModel* clientModel;
	WalletModel *walletModel;
    Ui::MyAliasListPage *ui;
    AliasTableModel *model;
    OptionsModel *optionsModel;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *deleteAction; // to be able to explicitly disable it
    QString newAliasToSelect;

private slots:
    /** Create a new alias */
    void on_newAlias_clicked();
    /** Copy alias of currently selected alias entry to clipboard */
    void on_copyAlias_clicked();

    /** Copy value of currently selected alias entry to clipboard (no button) */
    void onCopyAliasValueAction();
    /** Edit currently selected alias entry (no button) */
    void onEditAction();
    /** Export button clicked */
    void on_exportButton_clicked();
    /** transfer the alias to a syscoin address  */
    void onTransferAliasAction();
	void on_refreshButton_clicked();

    /** Set button states based on selected tab and selection */
    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for alias book entry */
    void contextualMenu(const QPoint &point);
    /** New entry/entries were added to alias table */
    void selectNewAlias(const QModelIndex &parent, int begin, int /*end*/);

signals:
    void transferAlias(QString addr);
};

#endif // MyAliasListPage_H
