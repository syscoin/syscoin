#ifndef AllOfferListPage_H
#define AllOfferListPage_H

#include <QDialog>

namespace Ui {
    class AllOfferListPage;
}
class OfferTableModel;
class OptionsModel;
class COffer;
QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
QT_END_NAMESPACE

/** Widget that shows a list of owned offeres.
  */
class AllOfferListPage : public QDialog
{
    Q_OBJECT

public:

    explicit AllOfferListPage(QWidget *parent = 0);
    ~AllOfferListPage();

    void setModel(OfferTableModel *model);
    void setOptionsModel(OptionsModel *optionsModel);
    const QString &getReturnValue() const { return returnValue; }
	bool handleURI(const QString& strURI, COffer* offerOut);
private:
    Ui::AllOfferListPage *ui;
    OfferTableModel *model;
    OptionsModel *optionsModel;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *deleteAction; // to be able to explicitly disable it
    QString newOfferToSelect;

private slots:
    /** Copy offer of currently selected offer entry to clipboard */
    void on_copyOffer_clicked();
    /** Copy value of currently selected offer entry to clipboard (no button) */
    void onCopyOfferValueAction();

    /** Export button clicked */
    void on_exportButton_clicked();

    /** Set button states based on selected tab and selection */
    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for offer book entry */
    void contextualMenu(const QPoint &point);

};

#endif // AllOfferListPage_H
