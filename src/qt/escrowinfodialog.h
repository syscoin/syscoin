#ifndef ESCROWINFODIALOG_H
#define ESCROWINFODIALOG_H
#include <QDialog>
class PlatformStyle;
class QDataWidgetMapper;
namespace Ui {
    class EscrowInfoDialog;
}
QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE
/** Dialog for editing an address and associated information.
 */
class EscrowInfoDialog : public QDialog
{
    Q_OBJECT

public:
    explicit EscrowInfoDialog(const PlatformStyle *platformStyle, const QModelIndex &idx, QWidget *parent=0);
    ~EscrowInfoDialog();
private:
	bool lookup();
private Q_SLOTS:
	void on_okButton_clicked();
private:
	const PlatformStyle *platformStyle;
	QDataWidgetMapper *mapper;
    Ui::EscrowInfoDialog *ui;
	QString GUID;
};

#endif // ESCROWINFODIALOG_H
