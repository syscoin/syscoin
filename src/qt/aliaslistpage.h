#ifndef ALIASLISTPAGE_H
#define ALIASLISTPAGE_H

#include <QDialog>

namespace Ui {
    class AliasListPage;
}
class AliasTableModel;
class OptionsModel;
class WalletModel;
QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
class QKeyEvent;
QT_END_NAMESPACE

/** Widget that shows a list of owned aliases.
  */
class AliasListPage : public QDialog
{
    Q_OBJECT

public:
   

    explicit AliasListPage(QWidget *parent = 0);
    ~AliasListPage();


    void setModel(WalletModel*, AliasTableModel *model);
    void setOptionsModel(OptionsModel *optionsModel);
    const QString &getReturnValue() const { return returnValue; }
    bool handleURI(const QString &uri);
	void keyPressEvent(QKeyEvent * event);
	void showEvent ( QShowEvent * event );
private:
    Ui::AliasListPage *ui;
    AliasTableModel *model;
    OptionsModel *optionsModel;
	WalletModel* walletModel;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *deleteAction; // to be able to explicitly disable it
    QString newAliasToSelect;

private slots:
    void on_searchAlias_clicked();
    /** Create a new alias for receiving coins and / or add a new alias book entry */
    /** Copy alias of currently selected alias entry to clipboard */
    void on_copyAlias_clicked();
    /** Copy value of currently selected alias entry to clipboard (no button) */
    void onCopyAliasValueAction();

    /** Export button clicked */
    void on_exportButton_clicked();
    /** transfer the alias to a syscoin address  */
    void onTransferAliasAction();

    /** Set button states based on selected tab and selection */
    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for alias book entry */
    void contextualMenu(const QPoint &point);
    /** New entry/entries were added to alias table */
    void selectNewAlias(const QModelIndex &parent, int begin, int /*end*/);

signals:
    void transferAlias(QString addr);
};

#endif // ALIASLISTPAGE_H
